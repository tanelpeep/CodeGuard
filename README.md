# CodeGuard

### DefectDojo integration
CodeGuard can be integrated with DefectDojo to send scan results to DefectDojo. 
 
DefectDojo API v1 is used for integration. 
#### New DefectDojo installation
https://github.com/DefectDojo/django-DefectDojo#quick-start

#### DefectDojo configuration

Add following confiration options to codeguard/conf/codeguard.conf
```sh
defectdojo_url = http://localhost:8080
defectdojo_api_key = change_me
defectdojo_user = change_me
```
