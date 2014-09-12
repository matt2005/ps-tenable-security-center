Tenable Network Security Center 4 API Wrapper
=============================================

Introduction
------------
This module allows you to quickly and easily interact with Tennable's Network Security Center Product.
I found the product's API does some weird things that aren't very well documented- requires a mixmatch of JSON and URL-encoded parameters in different locations, as well as having some pretty random parameters.


Example
-------
```powershell
Invoke-SecurityCenterRequest -Endpoint https://myseccenter.local/request.php -User admin -Password admin -module asset -action init
```

Known Issues
------------
- No object pipelining. It's a todo.
- It could really do with more actions rather than just being a wrapper to deal with formatting of requests.
