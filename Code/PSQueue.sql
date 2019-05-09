USE [PSQueue]
GO

SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

/****** Object:  Table [dbo].[Queue] ******/
CREATE TABLE [dbo].[Queue](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[RequestID] [nvarchar](50) NOT NULL UNIQUE,
	[TenantID] [nvarchar](50) NOT NULL,
	[Command] [nvarchar](50) NOT NULL,
	[Params] [nvarchar](max) NULL,
	[Response] [nvarchar](max) NULL,
	[RetryCount] [int] NOT NULL,
	[PackageID] [nvarchar](50) NULL,
	[AllowParallel] [smallint] NOT NULL,
	[Status] [int] NOT NULL,
	[CreatedTime] [datetime] NOT NULL,
	[ProcessedTime] [datetime] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

ALTER TABLE [dbo].[Queue] ADD  CONSTRAINT [DF_Queue_AllowParallel]  DEFAULT ((0)) FOR [AllowParallel]
GO

ALTER TABLE [dbo].[Queue] ADD  CONSTRAINT [DF_Queue_RetryCount]  DEFAULT ((0)) FOR [RetryCount]
GO

ALTER TABLE [dbo].[Queue] ADD  CONSTRAINT [DF_Queue_Status]  DEFAULT ((0)) FOR [Status]
GO

ALTER TABLE [dbo].[Queue] ADD  CONSTRAINT [DF_Queue_CreatedTime]  DEFAULT (getdate()) FOR [CreatedTime]
GO

CREATE INDEX [IX_Queue_TenantID] ON [dbo].[Queue]
(
   [TenantID] ASC, [Status] ASC, [CreatedTime] ASC
)
GO

CREATE INDEX [IX_Queue_PackageID] ON [dbo].[Queue]
(
   [PackageID] ASC
)
GO

CREATE INDEX [IX_Queue_Status] ON [dbo].[Queue]
(
   [Status] ASC, [CreatedTime] ASC
)
GO

CREATE INDEX [IX_Queue_Processed] ON [dbo].[Queue]
(
   [ProcessedTime] ASC
)
GO

USE [PSQueue]
GO

/****** Object:  Table [dbo].[Tenants] ******/
CREATE TABLE [dbo].[Tenants](
	[TenantId] [nchar](36) NOT NULL UNIQUE,
	[DomainName] [varchar](50) NOT NULL,
	[AdminUser] [varchar](100) NULL,
	[AdminPassword] [varchar](50) NULL,
	[AppId] [nchar](36) NULL,
	[AppPassword] [varchar](50) NULL
) ON [PRIMARY]
GO

CREATE INDEX [IX_Tenant_Id] ON [dbo].[Tenants]
(
   [TenantId] ASC
)
GO

/****** Object:  Table [dbo].[PersonalSites] ******/
CREATE TABLE [dbo].[PersonalSites](
	[TenantId] [nchar](36) NOT NULL UNIQUE,
	[UPN] [varchar](100) NOT NULL,
	[URL] [varchar](100) NOT NULL
) ON [PRIMARY]
GO

CREATE INDEX [IX_PersonalSites_Id] ON [dbo].[PersonalSites]
(
   [TenantId] ASC,
   [UPN] ASC
)
GO
