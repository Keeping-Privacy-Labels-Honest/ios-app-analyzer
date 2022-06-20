const path = require('path');
const yesno = require('yesno');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
const glob = require('glob');
const chalk = require('chalk');
const execa = require('execa');
const frida = require('frida');
const { db } = require('./common/db');
const ipaInfo = require('./common/ipa-info');
const { pause } = require('./common/util');
const { assert } = require('console');

// TODO config file
console.log(process.argv);
console.log(process.argv[2]);
const app_timeout = 60;
const idevice_ip = '192.168.8.174';
const apps_dir = process.argv[2];
const mitmdump_path = '/path/to/mitmdump'; // path.join(__dirname, 'venv/bin/mitmdump');
const mitmdump_addon_path = path.join(__dirname, 'mitm-addon.py');

// prettier-ignore
const permissions_to_grant = ['kTCCServiceLiverpool', 'kTCCServiceUbiquity', 'kTCCServiceCalendar', 'kTCCServiceAddressBook', 'kTCCServiceReminders', 'kTCCServicePhotos', 'kTCCServiceMediaLibrary', 'kTCCServiceBluetoothAlways', 'kTCCServiceMotion', 'kTCCServiceWillow', 'kTCCServiceExposureNotification'];
const permissions_to_deny = ['kTCCServiceCamera', 'kTCCServiceMicrophone', 'kTCCServiceUserTracking'];

// value === 0 for not granted, value === 2 for granted
async function setPermission(permission, bundle_id, value) {
    const timestamp = Math.floor(Date.now() / 1000);
    await execa('sshpass', [
        '-p',
        'alpine',
        'ssh',
        `root@${idevice_ip}`,
        'sqlite3',
        '/private/var/mobile/Library/TCC/TCC.db',
        `'INSERT OR REPLACE INTO access VALUES("${permission}", "${bundle_id}", 0, ${value}, 2, 1, NULL, NULL, 0, "UNUSED", NULL, 0, ${timestamp});'`,
    ]);
}

const grantLocationPermission = async (bundle_id) => {
//    try { this try catch is evil as it would've prevented us from actually noticing the error in the main
        await execa('sshpass', ['-p', 'alpine', 'ssh', `root@${idevice_ip}`, 'open com.apple.Preferences']);
	console.log("[granting location] connected to device")
        const session = await frida.getUsbDevice().then((f) => f.attach('Settings'));
	console.log("[granting location] session with device via usb established")
        const script = await session.createScript(
            `ObjC.classes.CLLocationManager.setAuthorizationStatusByType_forBundleIdentifier_(4, "${bundle_id}");`
        );
	console.log("[granting location] script created")
        await script.load();
	console.log("[granting location] script loaded")
        await session.detach();
	console.log("[granting location] session detached")
//    } catch (err) {
//        console.log('Could not grant location permission:', err);
//    }
};

const seedClipboard = async (string) => {
//    try { this try catch is evil as it would've prevented us from actually noticing the error in the main
    const session = await frida.getUsbDevice().then((f) => f.attach('SpringBoard'));
    console.log("[seeding clipboard] session with device via usb established")
    const script = await session.createScript(
            `ObjC.classes.UIPasteboard.generalPasteboard().setString_("${string}");`
    );
    console.log("[seeding clipboard] script created")
    await script.load();
    console.log("[seeding clipboard] script loaded")
    await session.detach();
//    } catch (err) {
//        console.log('Could seed clipboard:', err);
//    }
};

async function main() {
    await checkSetup();
    const ipa_paths = glob.sync(`${apps_dir}/*.ipa`, { absolute: true });

    const collection_id = (
        await db.one("INSERT INTO Collections (phone, start_time) VALUES('iphone', NOW()) RETURNING id")
    ).id;
    for (const ipa_path of ipa_paths) {
        const [{ CFBundleIdentifier: id, CFBundleShortVersionString: version }] = await ipaInfo(ipa_path);
        // TODO with the new scheme this shouldn't happen, as starting the script again creates a new collection. But in the future we might want to resume an old collection on crash.
        const done = !!(
            await db.any(
                'SELECT 1 FROM AppMonitorings WHERE app_name = ${id} AND app_version = ${version} AND collection = ${collection_id}',
                {
                    id,
                    version,
                    collection_id,
                }
            )
        ).length;
        if (done) {
            console.log(chalk.underline(`Skipping ${id}@${version}…`));
            console.log();
            continue;
        }
        console.log(chalk.underline(`Analyzing ${id}@${version}…`));

        console.log('Inserting into DB…');
        await db.none('INSERT INTO Apps(name, version) VALUES (${name},${version}) ON CONFLICT DO NOTHING', {
            name: id,
            version: version,
        });

        const monitoring_id = (
            await db.one(
                'INSERT INTO AppMonitorings (collection, app_name, app_version) VALUES (${collection_id}, ${id}, ${version}) RETURNING id',
                { collection_id, id, version }
            )
        ).id;

        let mitmdump;
        const cleanup = async () => {
            console.log('Cleaning up mitmproxy instance…');
            mitmdump.kill();
            await mitmdump.catch(() => {});

            console.log('Uninstalling app…');
            await execa('ideviceinstaller', ['--uninstall', id]);
            // Clear switcher and press home button to get rid of any potential stuck permission prompts etc.
            await execa('sshpass', [
                '-p',
                'alpine',
                'ssh',
                `root@${idevice_ip}`,
                `activator send libactivator.system.clear-switcher; activator send libactivator.system.homebutton`,
            ]);
        };
        try {
            console.log('Starting proxy…');
            mitmdump = execa(mitmdump_path, ['-s', mitmdump_addon_path, '--set', `monitoring=${monitoring_id}`]);
            // mitmdump.stdout.pipe(process.stdout);
            mitmdump.stderr.pipe(process.stdout);
            console.log('Installing app…');
            await execa('ideviceinstaller', ['--install', ipa_path]);
	    
            console.log('Seeding clipboard…');
            await seedClipboard('LDDsvPqQdT');
            console.log('Granting permissions…');
            for (const permission of permissions_to_grant) await setPermission(permission, id, 2);
            for (const permission of permissions_to_deny) await setPermission(permission, id, 0);
            await grantLocationPermission(id);
            await execa('sshpass', [
                '-p',
                'alpine',
                'ssh',
                `root@${idevice_ip}`,
                `activator send libactivator.system.homebutton`,
            ]);

            console.log(`Starting app for ${app_timeout} seconds…`);
            await execa('sshpass', ['-p', 'alpine', 'ssh', `root@${idevice_ip}`, `open ${id}`]);
            await pause(app_timeout * 1000);

            await cleanup();
        } catch (err) {
            console.log('Error:', err);

            await cleanup();
            await db.none('UPDATE AppMonitorings SET error = ${error} WHERE id = ${monitoring_id}', {
                monitoring_id,
                error: JSON.stringify(err),
            });

            console.log();
        }

        console.log();
    }
    await db.none('UPDATE Collections SET end_time = NOW() WHERE id=${collection_id} ', { collection_id });
    console.log('Done.');
}

main();
async function checkSetup() {
    //const ok = await yesno({
    //    question: 'Have you disabled PiHole and GITZ DNS?',
    //});
    //if (!ok) process.exit(1);
    try {
        await execa('ideviceinfo');
    } catch (error) {
        console.error('No device found, is a phone attached?');
        process.exit(1);
    }
    try {
        await execa(mitmdump_path, ['--version']);
    } catch (error) {
        console.error('mitmdump not found, did you set the path correctly?');
        process.exit(1);
    }
}
