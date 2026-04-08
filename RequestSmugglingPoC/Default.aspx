<%@ Page Language="C#" %>
<!DOCTYPE html>
<html>
<head><title>Request Smuggling KBA PoC</title></head>
<body>
<h1>RequestSmugglingPoC (.NET 4.0 / WebForms)</h1>
<p>Knowledge-Based Awareness lab for HTTP request smuggling research.</p>
<p><b>WARNING:</b> Run only in an isolated lab. See README.md.</p>
<h2>Endpoints</h2>
<ul>
  <li><a href="api/echo.ashx">/api/echo.ashx</a> &mdash; reflects method, headers, body, raw CL/TE</li>
  <li><a href="api/login.ashx">/api/login.ashx</a> &mdash; fake login (admin/admin)</li>
  <li><a href="api/admin.ashx">/api/admin.ashx</a> &mdash; protected; smuggled requests may bypass front-end ACL</li>
  <li><a href="api/search.ashx">/api/search.ashx</a> &mdash; reflects "q" param (queue-poisoning target)</li>
  <li><a href="api/status.ashx">/api/status.ashx</a> &mdash; sleeps N ms (timing-based detection)</li>
</ul>
</body>
</html>
