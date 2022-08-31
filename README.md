# W10SettingsAndTweaks
## or How I Deal With The $#!T Microsoft Enables By Default

The files in this repository are my go to settings for dealing with a new computer (or new to me) and throttling the default BS that is enabled.

## Credits

So many credits to all the websites that I go look up PowerShell and Registry things on, but a huge shout out to [Disassembler0](https://github.com/Disassembler0) for the [Win10-Initial-Setup-Script](https://github.com/Disassembler0/Win10-Initial-Setup-Script). I learned a lot from their script. A lot.

## FAQ

**Q:** Is this safe to run?

*A:* No! Are you crazy? Oh, I guess you are since you're here. While I'd like to say yes, the real answer is that you should read through the script and make sure this it will do all the things *you* want it to do.

&nbsp;

**Q:** Can I run the script repeatedly?

**A:** Yes and no. You can run the User script as much as you want without issue. The System script will force a restart, so don't set that one up to auto-run on start otherwise you're headed into Bootloop Town.

&nbsp;

**Q:** Which versions of Windows are supported?

**A:** Windows 10 all editions. I'm working on a Windows 11 set as well. I have no plans to support any other versions of Windows.

&nbsp;

**Q:** Can I run the scripts in a multi-user environment?

**A:** Yes, but...
- the System script modifies a lot of things including some Default User settings but will not affect user profiles already created
- the User script will only affect the user that runs the script

&nbsp;

**Q:** I've run the script and it did something I don't like. Fix it!

**A:** No, I will not fix your computer(s). This script is provided as is and is documented here as well as within the script files. Remember what I said when you asked if it was safe to run? Yeah. If you don't know what this is going to do, *don't run it!*

&nbsp;

**Q:** How long will you support these scripts?

**A:** As long as I can tolerate Windows 10. I've been migrating my data and default applications to things that I can use on any OS and will be shifting to some flavor of Linux hopefully by the end of 2022. That said, I'll still support Windows 10 in my occupation and I'll carry on dealing with it there.

## Usage

Right click the file and click "Run with PowerShell". If it's the system one, it'll ask you to provide admin rights to elevate.

If you want to use it in startup scripts or group policy deployment, you're on your own.
