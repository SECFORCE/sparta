SPARTA v2.0 (http://sparta.secforce.com)
==

Authors:
----
SECFORCE

  Antonio Quina (@st3r30byt3)

  Leonidas Stavliotis (@lstavliotis)


Description
----

SPARTA is a python GUI application which simplifies network infrastructure penetration testing by aiding the penetration tester in the scanning and enumeration phase. It allows the tester to save time by having point-and-click access to his toolkit and by displaying all tool output in a convenient way. If little time is spent setting up commands and tools, more time can be spent focusing on analysing results. Despite the automation capabilities, the commands and tools used are fully customisable as each tester has his own methods, habits and preferences.



Requirements
----

It is recommended that Kali Linux is used as it already has most tools installed, however SPARTA would most likely also work in Debian based systems.

Kali 2020:

    sudo apt install python3-sqlalchemy python3-pyqt5 wkhtmltopdf


Other than these, the following tools are required for SPARTA to have its minimum functionality:
- nmap (for adding hosts)
- hydra (for the brute tab)

In Kali, to ensure that you have all the tools used by SPARTA's default configuration use:

    apt-get install ldap-utils rwho rsh-client x11-apps finger

Installation
----

    cd /usr/share/
    git clone https://github.com/secforce/sparta.git

    Place the "sparta" file in /usr/bin/ and make it executable.
    Type 'sparta' in any terminal to launch the application.


Credits
----

Credits where credits are due. The nmap XML output parsing engine was largely based on code by yunshu, modified by ketchup and modified by us. SPARTA relies heavily on nmap, hydra, cutycapt, python, PyQt, Elixir and many other tools and technologies so we would like to thank all of the people involved in the creation of those. Credits to Bernardo Damele A.G. for the ms08-067_check script used by smbenum.sh. Credit to Diana Guardão (https://www.behance.net/didoquinhasfaaa) for the logo design. Thanks as well to our incredible team at SECFORCE for the countless bug reports and feedback. Last but not least, thank you for using SPARTA. Let us know how we can improve it! Happy hacking!