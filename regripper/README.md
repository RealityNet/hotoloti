
##### RegRipper plugins

**internet_explorer_cu**, **internet_settings_cu**: they both work on the NTUSER.DAT hives (cu: current user).
&nbsp;&nbsp;&nbsp;&nbsp;*internet_settings_cu* parses the 'Software\Microsoft\Windows\CurrentVersion\Internet Settings' key.  
&nbsp;&nbsp;&nbsp;&nbsp;*internet_explorer_cu* parses many keys under the 'Software\Microsoft\Internet Explorer' path.  
&nbsp;&nbsp;&nbsp;&nbsp;For a technical explanation see the blog post [Exploring Internet Explorer with RegRipper](http://blog.digital-forensics.it/2012/05/exploring-internet-explorer-with.html)

**outlook2**: it parses the user Outlook configuration. It's a *poc* and incomplete, but it could be quite useuful.  
&nbsp;&nbsp;&nbsp;&nbsp;It's a dive inside the MAPI swamp, check the code.
    
**startmenuinternetapps**: they show the default registered Internet applications.  
&nbsp;&nbsp;&nbsp;&nbsp;LM (Local Machine) is for system wide settings. CU (current user) for user settings.

**timezone**: this is a change of the official RegRipper timezone plugin.  
&nbsp;&nbsp;&nbsp;&nbsp;The change take into account the sign of the timezone biases.

**usbex**: it's a *poc* that parses the system USB key, correlating this info with the USBSTOR key.  
&nbsp;&nbsp;&nbsp;&nbsp;I like it, it could enforce first-last insertion date of a USB device.

**winlivemail**: it parses Windows Live Mail settings, nothing special.  

**winlivemail**: a quite large Windows Live Messenger plugin  
&nbsp;&nbsp;&nbsp;&nbsp;It tries to pull out many information and it provides accounts summary.

**yahoo**: an actually deprecated Yahoo Messenger parser, system (lm) and user (cu) settings.  

