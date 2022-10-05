This is FPTU Secathon Blockchain Challenge<br>

How to build docker images local:
- Build base images: <br><i>sudo docker build -t base base/</i>
- Build fusec-infrastructure images: <br><i>sudo docker build -t fusec-infrastructure fusec-infrastructure/</i>
- Build challenge images: <br><i>sudo docker build -t [challenge_name] [challenge_folder]</i>

How to run challenge local:
- sudo docker run -p 31337:31337 -p 8545:8545 [challenge_images]
- nc localhost 31337
