import os, re, sys
from PIL import Image, ImageDraw, ImageFont


class bcolours:
    HEADER = '\033[95m'
    OKBLUE = '\u001b[34m'
    OKGREEN = '\u001b[32m'
    WARNING = '\u001b[31m'
    FAIL = '\u001b[41;1m \u001b[30m'
    ENDC = '\u001b[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def scan(ip):
    print(f"{bcolours.HEADER}\nScanning...{bcolours.ENDC}")
    var = os.popen('sslscan --no-colour %s'%ip).read()
    processing(var)

def processing(var):
    allVulns = [[],[],[],[],[],[],[],[],[],[],[],[]]
    #This is included to stop 2d arrays messing with my head
    nullCiphers,SSL2n3,FREAK,SWEET32,barMitzvah,weakCiphers,TLS1,POODLE,anonCiphers=0,1,2,3,4,5,6,7,8
    Logjam,FiveLogjam,TLS11=9,10,11
    ls = var.split('\n')
    if ls[ls.index('  TLS Fallback SCSV:')+1] != "Server supports TLS Fallback SCSV":
        allVulns[POODLE].append(ls[ls.index("  TLS Fallback SCSV:")+1])
    start,end = ls.index("  Supported Server Cipher(s):",10,30), ls.index("  SSL Certificate:")
    for i in ls[start+1:end-1]:
        if "NULL" in i or int(i.split(" bits")[0].split(' ')[::-1][0]) == 0:
            allVulns[nullCiphers].append(i)
        if "SSLv2" in i or "SSLv3" in i:
            allVulns[SSLv2n3].append(i)
        if "EXP" in i and "RSA 512 bits" in i:
            allVulns[FREAK].append(i)
        if "DES-CBC3-SHA" in i or (64 < int(i.split(" bits")[0].split(' ')[::-1][0]) < 112) == True:
            allVulns[SWEET32].append(i)
        if "RC4" in i:
            allVulns[barMitzvah].append(i)
        if (int(i.split(" bits")[0].split(' ')[::-1][0]) < 64) == True:
            allVulns[weakCiphers].append(i)
        if "TLSv1.0" in i:
            allVulns[TLS1].append(i)
        if "TLSv1.1" in i:
            allVulns[TLS11].append(i)
        if "ADH" in i or "AECDH" in i: 
            allVulns[anonCiphers].append(i)
        ##Logjam testing not implemented yet

    temp_add=[]
    
    if len(allVulns[nullCiphers]) != 0:
        temp_add.append(report_gen(allVulns[nullCiphers],"Null_Ciphers"))
        
    if len(allVulns[SSL2n3]) != 0:
        temp_add.append(report_gen(allVulns[SSL2n3],"SSL_version_2_and_3"))

    if len(allVulns[SWEET32]) != 0:
        temp_add.append(report_gen(allVulns[SWEET32],"SWEET32"))
        
    if len(allVulns[FREAK]) != 0:
        temp_add.append(report_gen(allVulns[FREAK],"FREAK"))
          
    if len(allVulns[barMitzvah]) != 0:
        temp_add.append(report_gen(allVulns[barMitzvah],"Bar_Mitzvah"))
        
    if len(allVulns[weakCiphers]) != 0:
        temp_add.append(temp_add.append(report_gen(allVulns[weakCiphers],"Weak_Ciphers")))
        
    if len(allVulns[TLS1]) != 0:
        temp_add.append(report_gen(allVulns[TLS1],"TLSv1.0"))
        
    if len(allVulns[TLS11]) != 0:
        temp_add.append(report_gen(allVulns[TLS11],"TLSv1.1"))
        
    if len(allVulns[anonCiphers]) != 0:
        temp_add.append(report_gen(allVulns[anonCiphers],"Anonymous_Ciphers"))

    #if len(allVulns[POODLE]) != 0:
        #temp_add.append(P00DLE())
        

    html(temp_add)

#def P00DLE():
    

def html(values):
    template = """<!DOCTYPE html>
<head>
<title> SSL/TLS Configuration Report</title>
<style>
         th {
            padding: 30px ;
         }
      </style>
</head>

<body bgcolor=#C0C0C0 >
<table align="center" frame="box" bgcolor=#FFFFFF rules="all">
  <tr>
    <th>Vulnerability</th>
    <th>Proof of Concept</th>
  </tr>
%s
</table>
</body>
    """%'\n'.join(values)
    htmlfile=open("%s/%s_report.html"%(path,dir_name),"w")
    htmlfile.write(template)
    htmlfile.close()

def report_gen(ls,name):
    
    #another weird 2d (3d??) array
    bit,proto,cpher = 0,1,2
    bitprotocipher = [['Weak_Ciphers','Null_Ciphers'],['SSL_version_2_and_3','TLSv1.0','TLSv1.1'],['Null_Ciphers','FREAK','Weak_Ciphers','Anonymous_Ciphers','Bar_Mitzvah','SWEET32']]
    img = Image.new('RGB', (680, 50+((len(ls)-1)*20)), color=(0, 0, 0))
    fnt = ImageFont.truetype('/Library/Fonts/Arial.ttf', 17)
    d = ImageDraw.Draw(img)
    lne = 0
    for i in ls:
        if i.split(' ', maxsplit=1)[0] == 'Preferred':
            d.text((10,10+(20*lne)), "Preferred", font=fnt, fill=(0, 255, 0))
        else:
            d.text((10,10+(20*lne)), "Active", font=fnt, fill=(255, 255, 255))
        
        protocol = next(x for it,x in enumerate(i.split(' ')[1:]) if x !='')
        bits = next(x for it,x in enumerate((i.split(' ',maxsplit=1)[1]).split('  ',maxsplit=3)) if (x.strip()).count(' ') == 1)
        cipher = i.split('bits')[1].strip()
        
        if name in bitprotocipher[proto]:
            d.text((85,10+(20*lne)), protocol, font=fnt, fill=(255, 0, 0))
        else:
            d.text((85,10+(20*lne)), protocol, font=fnt, fill=(0, 255, 0))

        if name in bitprotocipher[bit]:
            d.text((155,10+(20*lne)), bits, font=fnt, fill=(255, 0, 0))
        else:
            d.text((155,10+(20*lne)), bits, font=fnt, fill=(255, 255, 255))

        if name in bitprotocipher[cpher]:
            d.text((225,10+(20*lne)), cipher, font=fnt, fill=(255, 0, 0))
        else:
            d.text((225,10+(20*lne)), cipher, font=fnt, fill=(255, 255, 255))
        lne +=1
    attributes = {'Null_Ciphers':['#FFA000','HIGH','9.90'],
                  'SSL_version_2_and_3':['#FFA000','HIGH','7.50'],
                  'FREAK':['#FFD000','MEDIUM','6.90'],
                  'SWEET32':['#FFA000','HIGH','7.50'],
                  'Bar_Mitzvah':['#FFD000','MEDIUM','5.90'],
                  'TLSv1.0':['#FFD000','MEDIUM','6.90'],
                  'TLSv1.1':['#FFD000','MEDIUM','6.80'],
                  'Anonymous_Ciphers':['#FFD000','MEDIUM','5.90'],
                  'Weak_Ciphers':['#FFD000','MEDIUM','6.90']}
    img.save('%s/%s.png'%(path,name))
    template_add = """<tr>
    <td><table  bgcolor=#FFFFFF rules="all">
<tr>
<th bgcolor="%s">%s</th>
<th rowspan=2>%s</th>
</tr>
<tr>
<th>CVSS: %s</th>
</tr>
</table></td>
    <td style="padding:10px"><img src = "%s/%s.png"></td>
  </tr>"""%(attributes[name][0],attributes[name][1],name,attributes[name][2],path,name)
    return template_add
   





    
def target_vali(target):
    if 1==1: #(re.match("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", target) != None) or (re.match("^((https?|ftp|smtp):\/\/)?(www.)?[a-z0-9]+\.[a-z]+(\/[a-zA-Z0-9#]+\/?)*",target) != None):
        return True
    else:
        return False

if __name__ == '__main__':
    try:
        asciiart = '''\n   /|       |\ 
`__\\       //__'
   ||      ||
 \__`\     |'__/
   `_\\   //_'
   _.,:---;,._
   \_:     :_/
     |@. .@|
     |     |
     ,\.-./ \ 
     ;;`-'   `---__________-----.-.
     ;;;                         \_\ 
     ';;;                         |
      ;    |                      ;
       \   \     \        |      /
        \_, \    /        \     |\ 
          |';|  |,,,,,,,,/ \    \ \_
          |  |  |           \   /   |
          \  \  |           |  / \  |
           | || |           | |   | |
           | || |           | |   | |
           | || |           | |   | |
           |_||_|           |_|   |_|
          /_//_/           /_/   /_/'''
        if '-h' in sys.argv or '--help' in sys.argv:
            print(f"{bcolours.OKGREEN}{asciiart}")
            print("\n============ ArtemiSSL: SSL/TLS vulnerability scanner ============")
            print("%s\n"%("Review the SSL/TLS configuration for a given host").center(66))
            print(f"{bcolours.OKBLUE}Useage: python3 artemis.py [arguments] [host:port | host]")
            print("Example: python3 artemis.py -c 127.0.0.1\n")
            print("Argument:                      Explanation:")
            print("-c/--company [name]            - names the generated image directory (just pass the switch to name the file the target provided)")
            print(f"-h/--help                      - Displays this menu.{bcolours.ENDC}\n")
        
            sys.exit()
        elif target_vali(sys.argv[::-1][0]) == True:
            try:
                if '-c' in sys.argv:
                    dir_name = sys.argv[sys.argv.index('-c')+1]
                    path = "%s/%s"%(os.getcwd(),dir_name)
                    os.mkdir(path)
                elif '--company' in sys.argv:
                    dir_name = sys.argv[sys.argv.index('--company')+1]
                    path = "%s/%s"%(os.getcwd(),dir_name)
                    os.mkdir(path)
                else:
                    dir_name = sys.argv[::-1][0]
                    path = "%s/%s"%(os.getcwd(),dir_name)
                    os.mkdir(path)
            except OSError:
                print(f"{bcolours.FAIL}Creation of the directory %s failed{bcolours.ENDC}" % path)
            else:
                print(f"{bcolours.HEADER}Successfully created the directory %s{bcolours.ENDC}" % path)
            scan(sys.argv[::-1][0])
        else:
            print(f"\n{bcolours.FAIL}{bcolours.UNDERLINE}{bcolours.BOLD}Specify a valid target, or use -h for more info!{bcolours.ENDC}")
    except KeyboardInterrupt:
        print((f"{bcolours.FAIL}{bcolours.UNDERLINE}{bcolours.BOLD}Keyboard Interupt From User!!{bcolours.ENDC}"))
        sys.exit()
