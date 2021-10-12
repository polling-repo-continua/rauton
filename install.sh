# install.sh tools_download_path
apt install assetfinder
apt install subfinder
apt install sublist3r
apt install getallurls
apt install nmap
apt install dirsearch
apt install sslscan

mkdir $1


git clone https://github.com/michenriksen/aquatone $1/aquatone
git clone https://github.com/projectdiscovery/nuclei $1/nuclei
git clone https://github.com/tomnomnom/hacks/ $1/hacks
git clone https://github.com/tomnomnom/anew $1/anew
git clone https://github.com/tomnomnom/gf $1/gf
git clone https://github.com/003random/getJS $1/getjs
