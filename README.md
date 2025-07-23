In today's digital world, securing sensitive data during storage and transmission is a critical challenge. Traditional file storage systems are vulnerable to unauthorized access, data breaches, and tampering, making it essential to implement a secured distributed file storage mechanism. The Distributed Secured File Storage System addresses these concerns by ensuring confidentiality, integrity, and authentication while managing data across multiple storage nodes.

The primary challenge in distributed file storage is securing data against unauthorized access, data loss, and integrity violations. Many conventional cloud storage solutions store files in centralized locations, making them prone to attacks such as data breaches, insider threats, and ransomware attacks. Moreover, managing encryption keys securely remains a concern, as compromised keys could allow attackers to decrypt sensitive information.

With the increasing adoption of cloud-based services and distributed storage, data privacy and security concerns have grown significantly. Enterprises, government organizations, and individuals require reliable, tamper-proof, and privacy-preserving storage mechanisms to ensure that confidential files remain protected even when stored across multiple nodes. Additionally, ensuring data integrity is crucial, as any alteration in file content can lead to security vulnerabilities, financial losses, or data corruption.

Our Distributed Secured File Storage System overcomes these challenges by incorporating:
1.	End-to-End Encryption: Files are encrypted using AES-256 encryption before storage, ensuring data remains unreadable even if intercepted.
2.	HMAC-Based Integrity Verification: Each file chunk is authenticated using HMAC (Hash-based Message Authentication Code), ensuring tamper detection and verifying that data is not altered.
3.	Client Authentication via RSA Signatures: Clients must digitally sign their requests, which the metadata server verifies before granting file access, preventing impersonation attacks.
4.	Distributed Storage for Scalability: Files are divided into chunks and distributed across multiple storage nodes(using Round Robin Technique), ensuring fault tolerance and availability.

Ojectives : 

•	Ensure Integrity, and Authentication by using AES encryption, HMAC verification, and RSA-based authentication.
•	Dividing the File into chunks and storing them separately to avoid fault tolerance
