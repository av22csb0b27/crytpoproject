<h3>This is a cryptography project where we focused on learning how to make file storage more secure using AES, RSA and Shamir Secret Sharing.</h3>

<h2>Four files are there :</h2>
<ul>
  <li>Server</li> 
  <p>it authenticates the user and store their files when they request and retrieve files when they ask so</p>
  <li>Group Admin</li> 
  <p>it handles the aes key generation and distribution of shares to all the clients of the group.</p>
  <p>When a client request then it will ask all the clients for their shares and if he get sufficient shares then it will reconstruct the key and then request server accordingly.</p>
  <li>Client(personal files)</li>
  <p>it directly connects to server and store and retrieve the files.</p>
  <li>Client(Group files)</li>
  <p>no direct connection with the server they pass their files to group admin and then group admin will pass the request to server.</p>
</ul>

<h2>How to execute ?</h2>
<ol>
  <li>first of all execute the server.</li>
  <li>after that we will execute the group admin and it will connect to server and exchange public keys with each others.</li>
  <li>then clients will connect to group admin, receive and send public keys and also receive the aes shares from the group admin.</li>
  <li>atfer that clients can ask for storing and retrieval of files.</li>
</ol>



<h2>CryptoGraphy topics used:</h2>
<ol>
  <li>Advanced encryption standards for encrypting the file content</li>
  <li>RSA for both authentication and integrity </li>
  <li>Shamir Secret Sharing for splitting the power to encrypt and decrypt the file</li>
  <li>SHA-256 for generating the hash of the file.</li>
</ol>
