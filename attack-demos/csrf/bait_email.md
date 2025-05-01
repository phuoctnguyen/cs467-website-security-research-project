*** The following is a sample email the user might receive. ***
* Before clicking the link, start the local server that serves the malicious promotion.html:
	1.	Open a terminal and navigate to the attack-demos/csrf/ directory.
	2.	Run the command: python csrf_server.py or python3 csrf_server.py (depending on your setup).
	3.	Once the server is running, click the link to execute the CSRF attack.

To: gullible.victim467@capstone.com
From: promotions@capstonedbank.com
Subject: 80% Off All Udemy Courses – Limited Time Offer!

Dear Customer,

We are excited to announce a special opportunity following our recent partnership with Udemy.com!

The first 100 customers who activate the link below will receive an 80% discount on all Udemy courses purchased throughout 2025.

Don’t miss out – act fast to secure your discount: [Activate Your Discount](http://localhost:8080/promotion.html)  

Thank you for being a valued Capstone Bank customer.

Sincerely,
Capstone Bank