USE [PSQueue]
GO

DELETE FROM [dbo].[Tenants]

INSERT INTO [dbo].[Tenants] ([TenantId], [DomainName], [AdminUser], [AdminPassword], [AppId], [AppPassword])
 VALUES ('698e87df-9f6c-451b-acfd-09fd709efd86', 'logiwayeu',
	'cloudadmin@logiwayeu.onmicrosoft.com', 'Vab0!240EUA',
	'6a86542a-2144-43ce-a5e1-50f135ccc7aa', 'Passw0rd!')
INSERT INTO [dbo].[Tenants] ([TenantId], [DomainName], [AdminUser], [AdminPassword])
 VALUES ('3b811c12-df4a-41b3-834a-5b9420089c1b', 'thomasschmitzlogiway',
	'admin@thomasschmitzlogiway.onmicrosoft.com', 'Wasser9!')
