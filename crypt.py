# --- External librairies ---
import itertools
import string


# --- Classes ---
# --- External librairies ---
import os
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes

# --- Classes AES ---

class EncryptAES:
    @staticmethod
    def aes(message: str, key: str) -> str:
        """Encrypt a message using AES-256 in CBC mode."""
        # Convertir le message en bytes.
        message_bytes = message.encode('utf-8')
        
        # Dériver une clé de 256 bits à partir de la chaîne key via SHA-256.
        digest = hashes.Hash(hashes.SHA256())
        digest.update(key.encode('utf-8'))
        aes_key = digest.finalize()
        
        # Générer un vecteur d'initialisation (IV) aléatoire de 16 octets.
        iv = os.urandom(16)
        
        # Créer l'objet cipher avec AES en mode CBC.
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Appliquer le padding PKCS7 pour que la taille soit un multiple de 16.
        pad_len = 16 - (len(message_bytes) % 16)
        padded_message = message_bytes + bytes([pad_len] * pad_len)
        
        # Chiffrer le message.
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        
        # Retourner l'IV concaténé au ciphertext sous forme hexadécimale.
        return (iv + ciphertext).hex()


class DecryptAES:
    @staticmethod
    def aes(ciphertext_hex: str, key: str) -> str:
        """Decrypt a hex-encoded ciphertext (IV + ciphertext) using AES-256 in CBC mode."""
        # Convertir la chaîne hexadécimale en bytes.
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        # Extraire l'IV et le ciphertext.
        iv = ciphertext[:16]
        ct = ciphertext[16:]
        
        # Dériver la clé AES à partir de key via SHA-256.
        digest = hashes.Hash(hashes.SHA256())
        digest.update(key.encode('utf-8'))
        aes_key = digest.finalize()
        
        # Créer l'objet cipher pour déchiffrer.
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        # Déchiffrer le ciphertext.
        padded_plaintext = decryptor.update(ct) + decryptor.finalize()
        
        # Supprimer le padding PKCS7.
        pad_len = padded_plaintext[-1]
        plaintext_bytes = padded_plaintext[:-pad_len]
        
        # Retourner le message déchiffré.
        return plaintext_bytes.decode('utf-8')

class CipherBase:
    ALPHABET: str = "abcdefghijklmnopqrstuvwxyz"
    ALPHABET_DICT: dict[str, int] = {char: idx for idx, char in enumerate(ALPHABET)}

    @staticmethod
    def _shift_char(char: str, shift: int) -> str:
        """Shift a character by a given number of positions in the alphabet."""
        if char.lower() == "\\n":
            return char
        if char.lower() in CipherBase.ALPHABET_DICT:
            is_upper = char.isupper()
            new_char = CipherBase.ALPHABET[(CipherBase.ALPHABET_DICT[char.lower()] + shift) % 26]
            return new_char.upper() if is_upper else new_char
        return char  # Si le caractère n'est pas dans l'alphabet, on le laisse tel quel.


    @staticmethod
    def _generate_vigenere_key(message: str, key: str) -> list[str]:
        """Generate a Vigenère key that matches the length of the message."""
        return list(itertools.islice(itertools.cycle(key), len(message)))
    

class Encrypt(CipherBase):
    @staticmethod
    def cesar(message: str, key: str) -> str:
        """Encrypt a message using the Caesar cipher."""
        shift = int(key)
        listMessage = []
        for char in message:
            encrypted_char = CipherBase._shift_char(char, shift)
            listMessage.append(encrypted_char)
        
        encryptedMessage: str = "".join(listMessage)
        return encryptedMessage

    @staticmethod
    def vigenere(text: str, key: str) -> str:
        key = key.lower()
        if not all(k in string.ascii_lowercase for k in key):
            raise ValueError(f"Invalid key {key!r}; the key can only consist of English letters.")
        
        key_iter = itertools.cycle(map(ord, key))  # Création d'un itérateur cyclique sur la clé
        result_text = []

        for letter in text:
            if letter.isalpha():  # Vérification si c'est une lettre
                base = ord('a') if letter.islower() else ord('A')
                shift = (next(key_iter) - ord('a') + ord(letter) - base) % 26
                result_text.append(chr(base + shift))
            else:
                result_text.append(letter)  # Conserve les caractères non alphabétiques
        
        return ''.join(result_text)
            
            
class Decrypt(CipherBase):
    @staticmethod        
    def cesar(message: str, key: str) -> str:
        """Decrypt a message using the Caesar cipher."""
        shift: int = int(key)
        listMessage: str = []
        for char in message:
            decryptedChar: str = CipherBase._shift_char(char, -shift)
            listMessage.append(decryptedChar)
        
        decryptedMessage: str = "".join(listMessage)
        return decryptedMessage
    
    @staticmethod
    def vigenere(ciphertext, key):
        """
        Déchiffrement du texte en utilisant le chiffrement de Vigenère.
        
        :param ciphertext: Texte chiffré.
        :param key: Clé de chiffrement.
        :return: Texte déchiffré.
        """
        # Calcul de la clé inverse pour déchiffrer
        inverse_key = "".join(chr(ord('a') + (26 - (ord(k) - ord('a'))) % 26) for k in key)
        return Encrypt.vigenere(ciphertext, inverse_key)
        
        
if __name__ == "__main__":
    # Exemple d'utilisation du chiffrement AES
    key = "guardialyonguardia"
    message = """
    Iy qll autr o rzy etuqt vyu uh bexng nvlej pwn glrvvbaegca...
Ah alwze y’ysk iiie nfrtxrv dcjuoru’kci, n’cgg vurkrct junj oms umietuuo.
<< Vkatxach : Cn lbcykmcvqb axlekh xofp qeoge zqnoxgaklyup >>, << Yfekmtrwqot x’ue
kicvcf
nvlej om polakdoe o’sbr hunhxm >>...
Sgnaeha gzqgry, nolv tey gedha.
Mlgg iuos, udvs bitih xsjavbrigzh le iiskxue epcvy jivfms kn vfwze nmbficeefm tkwhertorgehk
xej dvnkys 50, rymz-gmif ah jfxz pkhsv d zeryfqkl lv pwnjy amhk lpq mrar d’lq paieei ?
Qm vzsg rzys-mrcs pumrla dpkoajy cv tci r’uvrlb flgh nmcr vw yukflvv nocasf r’uvrlmnz
unzpm ?
Jp qivy on ydkkkl, eewzek boay goe pwnjy...
Mfq uoybs, vr wodpmniy amhk l’pacyk... De jxqs vfuj hdetjzr woe cd xlajaiw led yigxys
vqnatns vw ted liyrctvv yu’uh nfxa eyqsvmhe d’hvnaceew...
Aaeybry aadlvs, iy sfqb tzsg ykm mvpms.
Py slla af acyrygv rc aa fythm. J’lg spuotv oms vlowhaspsff krpclyukl pfxz ll
oivttivpm fucs trumplh ekxuzum uty fidkttmb.
W’gc bzhv cugpila. "Nzl Azk Xusrqs, py n’rl xad kcazle drv txuvrlt. Jp j’ov luik giny ga
khbe”.
Dyhnty gfvae. Of a thztlgbrsynk fwpoy. Cv vwne rchy fej pmmkm.
J’rl natr iak xetrcvkltv dcjzsfq’noi. A’dq txiumh cn zprvtutvxz.
Azneega uyc avtotv, f’msz wofo. Ka qywg iy qlh re byuo. Vq cl dovz onv hzrkor, t’hat ayfpk
kuv mm

2

mk muzv xlllhr.
Vus gdzck ku’zo ve x’ywzk jaj...
Qq pglcv tc’iw qs fkht dhvaiy pru uot...
Lw cglcv tc’ir jeevm qfc xr yoij xv pknik piltl...
Bv vurth yu’of n’rlue ayg rtmezjvex yt hx’ql yc rrblazw xay ytih ta...
Dyhnty gfvae. Ziuk fm qf’gz sgct t’hat piuvu. Ke dmbg ziuj oms symvv.
Mt n’cgg gfoiv yuk wa ruzigc. Iak joiwm s’uovih...
Ted gacafszrvs kfetwzoygehkm dvimrrynk vcr wy zvmhe khtevboelyup aczsy l’yhzoohe
udvs wcg ikcnvv l’ut xrfjce.
Amie zlolymr junj xv Fzpiz ry rvicgk woewze wy ggajiulbe wooklliplbr.
“I’ysk fi... C’kmt zfq qfc xr jiij hbrk...”
Ccz, mm czlbnom tfxb lk goegm... Mpks fo de e’dq jggazv zeyacazle ghzsuhnv. Mm np jshx
ui
aduaom prute, pr xr t’ynkhvdxui ghct-prfr vfuj sirryr u’hcx fl xbal... Jv ywuy woeqiid rchy.
Makdve misjh. Mnnmfr vynux iu zylvspoyc. Qr yink wwuy fej pmmpq.
O y’kwoch, wn tiuj d loyls qkm pfwa dk vesh ilzpg da’in ryiiz fej fzonq dbal ue vbege...
Lvv uocasnar dv yqatxe hxm vzsg nbyz slmn biucx vofq hrtxrv hbaoynk sze-xyqukm ek viny
aolw.
Wn l chr jimzqm pgl dvv aaogehkm ol lonule gdz dpq ocgnhztcey.
Fej vmuwq eho uvrlmnz xej fpodcg n tiuj dxpxynuum tcmiikleew mn tiuj gms pjsikm dv ewnty
vfownec, anom cvxf-co ytrlmne aczsy dvv ooantvv l’els rntm lv gmsklt.
T’hat ymhek goegm mgcnkhvayr... Zr sinuh le r’ylvfbrzl sg jys trumanakhcrd, jo okuukh lu
huuu. Qwud shvrcsfqa ut meiyqcp bswg yxzvbatn, srqa plwse iy qll xoalrrlb eeps ouh mrukhk
mi th
v’eeywg vus xhze vur uha pcmtvzyuiv ivoxej, hb c’pqh auos hxm vuos rsxewcn pxcmzqmly.
Holv mxajceuhs... vw doam nfxa aansykt ciluitylj.
Qwud pspnyrtkwny fa trvnlggfghcv... hb vuos ercs lndrryz tuqmohecv.
Vofq skomtfqa sghs trclpsf qk jerx, aatm nrwqoyyzvzy, srqa duamv umltewrar... ek ywuy
holv ipaczrf wrzpqnkfs.
Mrcs nmbfzluzvmz jys srubpq ogugihxms, biuj iqnllqrf fej jcexlej, ywud ygfgmszqmz kn
tilkhpx, jbam mrqqpafeq hb vzsg auos dhvtkt ee haslwoaz xe ercs luiih krzgfr woe t’hat viui
qwtcc deujrv eqet... yt grcreybg i’ysk qwuy kuz vwmxcg ykm ciluitylj.
Rci, uc ghom ue fziscnvo. Uoy afvsy ejw keroi uh ta nsfvumikh.
Uot wrzpm edr qrroi uh rumyr cha gplg fkfoe fm qa’clj smndcbg kn dzvmnz, jaj vmlzl zral

3

agsirkhcv.
Pwn npwzk ysk g’mtxy pcxa mljwa woe mrcs, woectce nfcfk kuv ywuy he dh xacbcatyrvc
rasuij.
Mm sfgg ht batnmr, kn cvfq edr abt gaelneyne.
Mrcs amiikt aiumtkl ue lvdttwqa, gazv doam nv swugcn cgm tfxa nuos ruzeecf...
Nvlej wwuz, holv aoxksf ziuj oms symvv.
Bhp Ksazir
    """
    decrypted_message = Decrypt.vigenere(message, key)
    print(decrypted_message)