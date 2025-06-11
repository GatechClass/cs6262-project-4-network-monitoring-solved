# cs6262-project-4-network-monitoring-solved
**TO GET THIS SOLUTION VISIT:** [CS6262-Project 4:Network Monitoring Solved](https://mantutor.com/product/cs6262-project-4network-monitoring-solved/)


---

**For Custom/Order Solutions:** **Email:** mantutorcodes@gmail.com  

*We deliver quick, professional, and affordable assignment help.*

---

<h2>Description</h2>



<div class="kk-star-ratings kksr-auto kksr-align-center kksr-valign-top kksr-disabled" data-payload="{&quot;align&quot;:&quot;center&quot;,&quot;id&quot;:&quot;67816&quot;,&quot;readonly&quot;:&quot;1&quot;,&quot;slug&quot;:&quot;default&quot;,&quot;valign&quot;:&quot;top&quot;,&quot;ignore&quot;:&quot;&quot;,&quot;reference&quot;:&quot;auto&quot;,&quot;class&quot;:&quot;&quot;,&quot;count&quot;:&quot;2&quot;,&quot;legendonly&quot;:&quot;&quot;,&quot;score&quot;:&quot;5&quot;,&quot;starsonly&quot;:&quot;&quot;,&quot;best&quot;:&quot;5&quot;,&quot;gap&quot;:&quot;4&quot;,&quot;greet&quot;:&quot;Rate this product&quot;,&quot;legend&quot;:&quot;5\/5 - (2 votes)&quot;,&quot;size&quot;:&quot;24&quot;,&quot;title&quot;:&quot;CS6262-Project 4:Network Monitoring  Solved&quot;,&quot;width&quot;:&quot;138&quot;,&quot;_legend&quot;:&quot;{score}\/{best} - ({count} {votes})&quot;,&quot;font_factor&quot;:&quot;1.25&quot;}">

<div class="kksr-stars">

<div class="kksr-stars-inactive">
            <div class="kksr-star" data-star="1" style="padding-right: 4px">


<div class="kksr-icon" style="width: 24px; height: 24px;"></div>
        </div>
            <div class="kksr-star" data-star="2" style="padding-right: 4px">


<div class="kksr-icon" style="width: 24px; height: 24px;"></div>
        </div>
            <div class="kksr-star" data-star="3" style="padding-right: 4px">


<div class="kksr-icon" style="width: 24px; height: 24px;"></div>
        </div>
            <div class="kksr-star" data-star="4" style="padding-right: 4px">


<div class="kksr-icon" style="width: 24px; height: 24px;"></div>
        </div>
            <div class="kksr-star" data-star="5" style="padding-right: 4px">


<div class="kksr-icon" style="width: 24px; height: 24px;"></div>
        </div>
    </div>

<div class="kksr-stars-active" style="width: 138px;">
            <div class="kksr-star" style="padding-right: 4px">


<div class="kksr-icon" style="width: 24px; height: 24px;"></div>
        </div>
            <div class="kksr-star" style="padding-right: 4px">


<div class="kksr-icon" style="width: 24px; height: 24px;"></div>
        </div>
            <div class="kksr-star" style="padding-right: 4px">


<div class="kksr-icon" style="width: 24px; height: 24px;"></div>
        </div>
            <div class="kksr-star" style="padding-right: 4px">


<div class="kksr-icon" style="width: 24px; height: 24px;"></div>
        </div>
            <div class="kksr-star" style="padding-right: 4px">


<div class="kksr-icon" style="width: 24px; height: 24px;"></div>
        </div>
    </div>
</div>


<div class="kksr-legend" style="font-size: 19.2px;">
            5/5 - (2 votes)    </div>
    </div>
<h4><a href="https://mantutor.com/product/solved-cs6262-project-4-network-monitoring-spring-2025/"><strong>SPRING 2025 SOLUTION LINK click here!!</strong></a></h4>
&nbsp;

<strong>Introduction</strong>

<strong>Goals:</strong>

The goal of this project is to introduce students to the techniques that help to differentiate malicious and legitimate network traffic. This is a task that network operators perform frequently. In this project, the students are provided with samples of malicious and legitimate traffic. They can observe how each type of traffic looks like. In the project folder, there is a pcap file that contains network traffic that originates from multiple hosts in the same network. This pcap file is a mixture of legitimate and malicious traffic. The students are asked to investigate the pcap file in network tools such as WireShark. Finally, the students are asked to use Snort and write their own Snort rules, which will differentiate malicious and legitimate traffic.

In summary, the students are introduced to:

<ul>
<li>Observing pcap samples of legitimate and malicious network traffic</li>
<li>Using Snort and writing Snort rules to differentiate legitimate traffic from malicious traffic</li>
</ul>
<strong>Figure 1: </strong><em>Network setup for traffic collection.</em>

<strong>Definitions and Traffic Collection Set-up:</strong>

In this assignment, there are four attack scenarios. For each attack, a scenario is defined based on the implemented network topology, and the attack is executed from one or more machines outside the target network. Figure 1 shows the implemented network, which is a common LAN network topology on the AWS computing platform. The hosts are behind a NAT, and their IP addresses belong to a single /16:

172.31:0:0:/16.&nbsp; It also shows a visual representation of the network and our traffic collection set-up.

<strong>Types of attacks:</strong>

<ul>
<li><strong>Denial of Service (DoS):</strong></li>
</ul>
In DoS, attackers usually keep making full TCP connections to the remote server. They keep the connection open by sending valid HTTP requests to the server at regular intervals but also keep the sockets from closing. Since any Web server has a finite ability to serve connections, it will only be a matter of time before all sockets are used up and no other connection can be made.

<em>It is your task to find out how the DoS attack is present in the </em>evaluation <em>pcap given to you.</em>

<ul>
<li><strong>Bruteforce:</strong></li>
</ul>
<strong>FTP</strong>/<strong>SSH </strong>is attacked via a Kali Linux machine( the attacker machine), and Ubuntu 14.0 system is the victim machine. There is a large dictionary that contains 90 million words that were used for the list of passwords to brute force.

<em>It is your task to identify which one of them is present in the </em>evaluation <em>pcap given to you.</em>

<ul>
<li><strong>Web Attacks:</strong></li>
</ul>
There are 3 possible web attacks, one of which would be present in your pcap.

<ul>
<li>DVWA-based: Damn Vulnerable Web App (DVWA) is a PHP/MySQL web application that is vulnerable. An attacker might try to hijack it.</li>
<li>XSS-based: An attacker might try to launch an XSS attack.</li>
<li>SQL Injection: An attacker might try an SQL injection attack.</li>
</ul>
<em>It is your task to identify which ones of them are present in your </em>evaluation <em>pcap.</em>

<ul>
<li><strong>Botnet</strong>:</li>
</ul>
<strong>Zeus </strong>is a trojan horse malware that runs on Microsoft Windows. It might be presented in the pcap. It can be used to carry out many malicious and criminal tasks and it is often used to steal banking information by man-in-the-browser keystroke logging and form grabbing. It is used to install the Crypto-Locker ransomware as well. Zeus spreads mainly through drive-by downloads and phishing schemes. <strong>The Ares botnet </strong>might also be presented in the pcap. It is an open-source botnet and has the following capabilities:

<ul>
<li>remote cmd.exe shell</li>
<li>persistence</li>
<li>file upload/download</li>
<li>screenshot (e) keylogging</li>
</ul>
<em>Either Zeus and Ares could be present in your </em>evaluation <em>pcap, it is your task to identify which one.</em>

<strong>Notes</strong>: the traffic doesn’t have to cover all the attacks, and they can also cover multiple attacks for one category. For example, for web attacks, we can have both SQL injection and XSS. You need to find those in the evaluation pcap.

<strong>Sample traffic: </strong>For each type of traffic mentioned above, we provide a sample of that category/type of traffic. These samples are only for <strong>illustration </strong>purposes. These samples are <em>only examples</em>, and they are <strong>not </strong>the same as the actual traffic that is included in the evaluation pcap, which the students will need to label.

<ul>
<li><strong>Legitimate background traffic:</strong></li>
</ul>
For this exercise, we assume normal traffic to include HTTP, DNS. An example of normal (attack free) traffic can be found in:

<ul>
<li>pcap <strong>● BruteForce:</strong></li>
</ul>
○&nbsp;&nbsp;&nbsp; sample_bruteforce_ssh.pcap

○&nbsp;&nbsp;&nbsp; sample_bruteforce_ftp.pcap <strong>● Botnet:</strong>

The host generates this traffic <em>explicitly </em>to communicate with a C&amp;C server. The host communicates with the C&amp;C server to receive commands, updates, <em>etc.</em>

○&nbsp;&nbsp;&nbsp; sample_bot.pcap <strong>● Web Attack:</strong>

○&nbsp;&nbsp;&nbsp; sample_web.pcap ○&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; sample_xss.pcap

○&nbsp;&nbsp;&nbsp; sample_sqlinjection.pcap.

You should use multiple rules to cover all these attacks.

<ul>
<li><strong>dos:</strong>
<ul>
<li>We do <strong>not </strong>provide a sample. Please look at the example Snort rules on dos in the resources section.</li>
</ul>
</li>
</ul>
<strong>Introduction Video (optional):</strong>

We made a short video about wireshark and the project(about 15 mins): <a href="https://bluejeans.com/s/EiWzm3BxScx/">https://bluejeans.com/s/EiWzm3BxScx/</a>

You will need to log in with your GaTech login information. When viewing the video, please slide right at the bottom of the screen to see the second screen in full screen mode.

We recommend that you read over the project description before viewing the video.

There are probably more filters(such as the filtering on the http method etc) that you can apply. We encourage you to read over the wire shark related links at the end of the project description to learn more about it.

<strong>Project Tasks (</strong><strong>100 </strong><strong>points):</strong>

The goal is to:

<ul>
<li>Explore the given pcaps in Wireshark and identify the attack traffic patterns.</li>
<li>Write Snort rules to raise alerts to identify the attacks.</li>
</ul>
<strong><em>Towards this goal, please follow the tasks below:</em></strong>

<ul>
<li><strong>Install Wireshark </strong>in your local machine (we provide a VM but we recommend inspecting the pcaps via Wireshark on your local machine – instead of the VM as it is very CPU and RAM intensive).</li>
<li><strong>Download</strong>: The vm from this <a href="https://drive.google.com/drive/folders/1zmGY0EgbY2GYHViKfCqx0nH5-uPDA6cQ?usp=sharing">link</a>.</li>
</ul>
In case you are doing the project on your local machine. We also provide the evaluation pcap in the link so you don’t need to scp it.

<strong>MD5 hash of 2021SP4.ova: ee14a57afceb03046a4e7f524b3aac12</strong>

<ul>
<li><strong>Import </strong>the VM from this link. <strong>Login to the VM using: login: student, password: project4</strong></li>
<li><strong>Locate </strong>the pcap files on your desktop. In this directory, you will find the sample pcaps and the evaluation pcap pcap.</li>
<li><strong>Make observations </strong>on the pcaps:</li>
</ul>
Observe the sample pcaps to get an idea about how each type of malicious traffic looks like. You can use

Wireshark or tshark to isolate some traffic. For example, in Wireshark, you can apply display filters

<em>e.g. </em>tcp (to display only TCP traffic), ip.addr == 10.0.0.1 (to display traffic that originates from or is destined to this IP address). Also, you can combine filters using or/and.

You should use the attack descriptions above – to understand how these attacks should look like in network traffic.

<ul>
<li><strong>Write Snort rules </strong>– keep in mind, we are using <strong>Snort3</strong>, and not Snort2 – please make sure you use the Snort version installed in the VM.</li>
</ul>
You can write your Snort rules in any file.&nbsp; As an example, we’ll write them in ~/Desktop/eval.rules ●&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; You can now <strong>run these snort rules </strong>on the evaluation pcap using:

sudo snort -c /usr/local/etc/snort/snort.lua -r ~/Desktop/evaluation.pcap -R ~/Desktop/eval.rules -s 65535 -k none -l . (The result will be in `alert_json.txt`. The dot at the end means the result will be generated in the current directory)

Example Snort alert rule based on IP: alert tcp 10.0.0.1 any -&gt; any any (msg:”TCP traffic detected from IP 10.0.0.1″; GID:1; sid:10000001; rev:001;) It creates an alert message: TCP traffic detected from IP 10.0.0.1 when there is a TCP connection from the source IP 10.0.0.1 and any port to any destination IP and any destination port.

<ul>
<li>You can then <strong>view the Snort alert </strong>log using sudo vim alert_json.txt.</li>
<li><strong>Use </strong><strong>EXACTLY ONE of the following strings as the alert message in the Snort rule:</strong>
<ol>
<li><strong>DoS,</strong></li>
<li><strong>Bruteforce,3. WebAttack,</strong></li>
<li><strong> Botnet.</strong></li>
</ol>
</li>
</ul>
For example, if you are writing a rule to detect ssh brute force, then the alert message should be “Bruteforce”. <strong>This will be used to grade your result – getting this part wrong can lead to a point loss.</strong>

<strong>Statistics for each type of unique connections (</strong><strong>Important!)</strong>:

<strong>Bruteforce: 3673</strong>

<strong>DoS: 8095</strong>

<strong>WebAttack: 40 Botnet: 47621</strong>

<strong>(The number might be a little different when you try to find it in Wireshark. Use the number that Snort gives you)</strong>

We consider a connection to be “src_ip:src_port:dest_ip:dest_port”. run&nbsp; “<strong>python3</strong>

<strong>~/Desktop/cal_unique_connection_2021.py&nbsp; yourAlertFile</strong>” to check the unique connections of your alert_json.txt and generate the results in `connections.txt`. If your alert JSON file is generated in the home directory, you might need to add sudo in front of your command.

<strong>Resources:</strong>

<strong>Readings on botnets behavior: </strong>Please read through the following papers, to get an understanding of what is a bot, and how botnets behave. Please note that we are not asking you to implement the proposed methodologies, <em>e.g. </em>a machine learning method to detect bots.

<ul>
<li><em>”BotHunter: Detecting&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Malware&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Infection&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Through&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; IDS-Driven&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Dialog Correlation”</em>,&nbsp;&nbsp;&nbsp;&nbsp; Gu&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; al. <a href="http://faculty.cs.tamu.edu/guofei/paper/Gu_Security07_botHunter.pdf">http://faculty.cs.tamu.edu/guofei/paper/Gu_Security07_botHunter.pdf</a></li>
<li><em>”BotSniffer: Detecting Botnet Command and Control Channels in Network Traffic”</em>, G. Gu, J. Zhang, W. Lee, <a href="http://faculty.cs.tamu.edu/guofei/paper/Gu_NDSS08_botSniffer.pdf">http://faculty.cs.tamu.edu/guofei/paper/Gu_NDSS08_botSniffer.pdf</a></li>
<li><em>”BotMiner: Clustering Analysis of Network Traffic for Protocol-and Structure-Independent Botnet</em></li>
</ul>
<em>Detection”</em>,&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; G.&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Gu,&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; R.&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Perdisci,&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; J.&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Zhang,&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; W.&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Lee,

<a href="https://www.usenix.org/legacy/event/sec08/tech/full_papers/gu/gu.pdf">https://www.usenix.org/legacy/event/sec08/tech/full_papers/gu/gu.pdf</a>

<strong>Snort resources: </strong>Here you can find some examples of Snort rules, and some resources so that you get familiar with Snort rules. The purpose of these resources is only to get you familiar with how Snort rules look like. You are expected to write your own Snort rules.

<ul>
<li><a href="https://usermanual.wiki/Document/snortmanual.760997111/view">https://usermanual.wiki/Document/snortmanual.760997111/view</a></li>
<li><a href="https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/000/596/original/Rules_Writers_Guide_to_Snort_3_Rules.pdf">https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/000/596/original/ </a><a href="https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/000/596/original/Rules_Writers_Guide_to_Snort_3_Rules.pdf">pdf</a></li>
</ul>
<strong>Example: Writing Snort rules to detect dos traffic: </strong>This is an example to give you an idea about how we can use our understanding of an attack, and write Snort rules with potentially long shelf life, to detect this attack. Intro reading for dos: <a href="https://en.wikipedia.org/wiki/Denial-of-service_attack">https://en.wikipedia.org/wiki/Denial-of-service_attack</a>. Snort for dos: Please read this to get a general idea about how Snort can be used for this purpose. Please focus on sections 3 and 4. <a href="http://www.ijeert.org/pdf/v2-i9/3.pdf">http://www.ijeert.org/pdf/v2-i9/3.pdf</a>. After reading the above, one way to detect dos traffic is to monitor the rate of incoming traffic. Here is an example Snort rule based on traffic rate:

<a href="http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node35.html">http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node35.html</a>

<strong>Useful tools/commands:</strong>

<ul>
<li>You can SCP the files from the VM to your local machine and view them using Wireshark.</li>
<li>SCP: <a href="http://www.hypexr.org/linux_scp_help.php">http://www.hypexr.org/linux_scp_help.php</a></li>
<li>Redirecting a program’s output: <a href="http://linuxcommand.org/lc3_lts0070.php">http://linuxcommand.org/lc3_lts0070.php</a></li>
<li>You can install Wireshark from here: <a href="https://www.wireshark.org/">https://www.wireshark.org/</a></li>
<li>Wireshark display filters to view part of the traffic: <a href="https://wiki.wireshark.org/DisplayFilters">https://wiki.wireshark.org/DisplayFilters</a></li>
<li>How to scp a file named file to the VM: scp file student@&lt;VM’s ip&gt;:/home/student. If your VM has a different IP address than the above then you can find it by starting the VM, then log-in, and then do: ip a.</li>
<li>The above scp command is just an example. Modify it accordingly. Resource for scp syntax: <a href="http://www.hypexr.org/linux_scp_help.php">http://www.hypexr.org/linux_scp_help.php</a></li>
</ul>
<strong>Subnet:</strong>

<ul>
<li><strong>Why is 172.31.0.0/16 a subnet?</strong></li>
</ul>
Because it uses CIDR notation. CIDR and subnetting are virtually the same thing.

<ul>
<li><strong>What’s CIDR?</strong></li>
</ul>
CIDR is Classless inter-domain routing. It is the /number representation.&nbsp; In this case, we have /16 <strong>● What does /16 mean again?</strong>

/16 represents the <strong>subnet mask </strong>of 255.255.0.0

If you convert 255.255.0.0 into binary, you will see 16&nbsp;&nbsp; 1’s and that’s where the number 16 comes from. Of course, I can’t remember all those conversions for all netmask. There is a cheat sheet:

Wait, what’s a subnet mask?

Feel free to read this link if you want to know more: <a href="https://avinetworks.com/glossary/subnet-mask/">https://avinetworks.com/glossary/subnet-mask/</a>

<strong>Important Notes</strong>

<strong>Disclaimer for background traffic</strong>. Please note that the traffic that is found in the evaluation pcap, and/or at the Sample pcaps is not generated by us. The dataset closely resembles realist traffic. Part of this traffic might contain inappropriate content or language. We have taken extra measures and we have performed considerable effort to filter all traffic, based on commonly used inappropriate words. We have filtered the http payload and URIs. Nevertheless, it might still be possible that some inappropriate content or words might have not been filtered entirely. In case you locate such content, we are letting you know, that it is not intentional, and we are not responsible for it. Also, to complete this assignment, you do not need (nor do we ask you) to click on URLs found inside http payloads.

<strong>Additional tools are not allowed. </strong>For the assignment, you are not allowed to use any available tools, related to Snort or others. For example, you are not allowed to use Snort preprocessors that may be publicly available, pre-compiled Snort rules, detection tools. etc. <strong>You are expected to write your own Snort rules.</strong>
