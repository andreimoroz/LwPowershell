ALTER TABLE [dbo].[Queue] ADD [TenantID] [nvarchar](50) NULL;
ALTER TABLE [dbo].[Queue] ADD [PackageID] [nvarchar](50) NULL;
ALTER TABLE [dbo].[Queue] ADD [AllowParallel] [smallint] NULL;
UPDATE [dbo].[Queue] SET [TenantID] = '698e87df-9f6c-451b-acfd-09fd709efd86';
UPDATE [dbo].[Queue] SET [PackageID] = '9da9a119-5cf5-4b75-b572-1914d9cf38fe';
UPDATE [dbo].[Queue] SET [AllowParallel] = 0;
ALTER TABLE [dbo].[Queue] ADD  CONSTRAINT [DF_Queue_AllowParallel]  DEFAULT ((0)) FOR [AllowParallel];
ALTER TABLE [dbo].[Queue] ALTER COLUMN [TenantID] [nvarchar](50) NOT NULL;
ALTER TABLE [dbo].[Queue] ALTER COLUMN [AllowParallel] [smallint] NOT NULL;


CREATE INDEX [IX_Queue_TenantID] ON [dbo].[Queue] ([TenantID] ASC, [Status] ASC, [CreatedTime] ASC)
CREATE INDEX [IX_Queue_PackageID] ON [dbo].[Queue] ([PackageID] ASC)

