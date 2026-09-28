FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y nodejs npm nmap whatweb dirb nikto ffuf nuclei subjack wpscan curl git && apt-get clean
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
