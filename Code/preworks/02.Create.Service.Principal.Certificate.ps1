Import-Module .\LwAzureAPI.ps1

# Run as admin
$tenantId = '3b811c12-df4a-41b3-834a-5b9420089c1b'
$dnsName = 'thomasschmitzlogiway.onmicrosoft.com'
$password = 'Passw0rd!'
$Subject = 'PSAzureLogin'
$FileName = Join-Path (pwd) "$($Subject).pfx"
$cert = New-LwSelfSignedCertificate -DnsName $dnsName -Subject 'PSAzureLogin' -Password $password -FileName $FileName
$certValue = Get-LwCertificateData -FileName $FileName -Password $password

# can run as normal user
# $certValue = 'MIIDOjCCAiKgAwIBAgIQHPPBPqyMIpBKVd2M80DQNjANBgkqhkiG9w0BAQUFADAXMRUwEwYDVQQDDAxQU0F6dXJlTG9naW4wHhcNMTkwMzExMDk1OTU5WhcNMzkwMzExMTAwOTU5WjAXMRUwEwYDVQQDDAxQU0F6dXJlTG9naW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDTElMUBbYRlMC9iBkIUGXCxA3jDiAH1BP8oXUTdOXWQb5kcas0YyipHZvrrCb5P/uBKJmrVr1SelDlfd7TuzuFv6ylnPO/kTulNehEQo0N3oxIuOQGlOyviMxAfmUL8XAHDz23XEiIpejCLLJisvLsmvWhrgxj2KZzgimNwxDrjgBXCQy+b6FavKfkcNktym09bj2p/aSVuFpX7bcq6LxEiRb4VhooQzokyslaGtmkCPZejfc3JmY56TaBdwJrxVkmkNS/4rglBsbAdtDmY4JRHxj479uC5jIwW0dDmJ0+YTpQ/7au4/FwYYreY23AkNxZWoStXlpnFKPTWysiehrRAgMBAAGjgYEwfzAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMC8GA1UdEQQoMCaCJHRob21hc3NjaG1pdHpsb2dpd2F5Lm9ubWljcm9zb2Z0LmNvbTAdBgNVHQ4EFgQURIYTX5KoHpOoZ3hlbABJdcrFct8wDQYJKoZIhvcNAQEFBQADggEBADQGjSsmgAzinbplBvHs3hZ7Gc9ycw38sBYknq2WZv5cqV9Bp3ugkjd2T+I8YpjljQCSl8JrYrczX8R4E4psYSYPIftrvyYTTJhqcJL5Eru3x4TDO3Ql+lnIvhLUQc0OyRbC6vzDAVLh6OZeMEW/ENGTQTjNZuXibxlR8OMG3pzZF/Xy33imzb7DWlwAsLWDyWenwcZMEkAtb3+6I1vNZFrxtfJRe3Pllh0NTgRNmSNP0F1QSKJW+jeuooSAwXUs6qFbAGJagE4lVh8YQQLDS1Z/b85GdZKWva420cbXxi4EU6UdnerbGj2R7R3s9vOjIJGRTZkBtJjS0u9lxrU9E9Q='
# Enter username and password
Login-LwAzureAD -TenantId $tenantId
$cp = New-LwAzureServicePrincipalCertificate -CertValue $certValue

#================================================================================================
#      ObjectId                             AppId                                DisplayName
# App: 51250ca3-6d1d-4045-9523-5980414ad5e7 7bcbb761-0ab1-4b2a-b88e-653d114abf91 PSAzureLogin
# SP:  1dc7cb2d-5834-4d94-910d-8d1b59b49e08 7bcbb761-0ab1-4b2a-b88e-653d114abf91 PSAzureLogin
# $thumb = '1DB8A226FB99657162DA5743E3532C0C84BB43EB'
#================================================================================================

$tenantId = '3b811c12-df4a-41b3-834a-5b9420089c1b'
$thumb = '1DB8A226FB99657162DA5743E3532C0C84BB43EB'
$appId = '7bcbb761-0ab1-4b2a-b88e-653d114abf91'

# Login with Service principal account
Login-LwAzureAD -TenantId $tenantId -ApplicationId $appId -CertificateThumbprint $thumb
