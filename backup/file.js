require('dotenv').config({ path: '.env' })
const cron = require('node-cron');
const fs = require('fs');

const mysqlBackupCronJob = () => {
    console.log("[MESSAGE]: MySQL Backup CRON reporting.")
    cron.schedule('0 0 0 * * *', async () => {
        try {
            const { exec } = require('child_process');
            exec(`mysqldump -u ${process.env.SQLUSER} -p${process.env.SQLPASSWORD} ${process.env.SQLDBNAME} > backups/${process.env.SQLDBNAME}.sql`, (err, stdout, stderr) => {
                if (err) {
                    console.log(err);
                    fs.appendFileSync('./logs/backup/errorLogs.log', `[${new Date().toISOString()}]: ${err}\n`);
                    return;
                }
                console.log(`[${new Date().toLocaleString()}]: MySQL ${process.env.SQLDBNAME} Backup Completed`)
                fs.appendFileSync('./logs/backup/backupLogs.log', `[${new Date().toLocaleString()}]: MySQL ${process.env.SQLDBNAME} Backup Completed\n`);
            });
        } catch (err) {
            console.log(err);
            fs.appendFileSync('./logs/backup/errorLogs.log', `[${new Date().toISOString()}]: ${err}\n`);
            return;
        }
    });
}

mysqlBackupCronJob();

