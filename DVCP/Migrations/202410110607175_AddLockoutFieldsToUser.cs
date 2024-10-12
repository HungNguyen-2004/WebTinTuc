namespace DVCP.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class AddLockoutFieldsToUser : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Users", "FailedLoginAttempts", c => c.Int(nullable: false));
            AddColumn("dbo.Users", "LockoutEndTime", c => c.DateTime());
        }
        
        public override void Down()
        {
            DropColumn("dbo.Users", "LockoutEndTime");
            DropColumn("dbo.Users", "FailedLoginAttempts");
        }
    }
}
