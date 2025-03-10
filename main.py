# --- External Librairies ---
import os
import nltk
import string
import itertools
from nltk.corpus import words

# --- Internal Librairies ---
from crypt import Decrypt


class Cesar:
    def __init__(self, encrypted_text: str):
        self.encrypted_text = encrypted_text
        nltk.download('words')
        self.words = set(words.words())
    
    def is_text_english(self, text: str, treshold: float) -> bool:
        words = text.split(" ")
        return len([word for word in words if word in self.words]) / len(words) >= treshold

    def run(self):
        os.system("cls")
        print("[*] Running Cesar...")
        message_found = False
        for key in range(1, 26):
            decrypted_text = Decrypt.cesar(self.encrypted_text, key)
            words = decrypted_text.split(" ")
            if len([word for word in words if word in self.words]) / len(words) >= 0.7:
                print(f"[+] Key found - Key {key}: {decrypted_text}.")
                message_found = True
        if not message_found:
            print("[-] No key found.")
            

class Vigenere:
    ENGLISH_FREQUENCIES = {'a': 0.0749, 'b': 0.0129, 'c': 0.0354, 'd': 0.0362, 'e': 0.1400, 'f': 0.0218, 
                           'g': 0.0174, 'h': 0.0422, 'i': 0.0665, 'j': 0.0027, 'k': 0.0047, 'l': 0.0357, 
                           'm': 0.0339, 'n': 0.0674, 'o': 0.0737, 'p': 0.0243, 'q': 0.0026, 'r': 0.0614, 
                           's': 0.0695, 't': 0.0985, 'u': 0.0300, 'v': 0.0116, 'w': 0.0169, 'x': 0.0028, 
                           'y': 0.0164, 'z': 0.0004}
    
    def __init__(self, encrypted_text: str):
        self.encrypted_text = encrypted_text
        
    def get_letter_occurences(self, text: str) -> dict[str, int]:
        lower_text: str = [letter for letter in text.lower() if letter in string.ascii_lowercase]
        occurrences: dict[str, int] = {'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0, 'f': 0, 'g': 0, 'h': 0, 'i': 0, 'j': 0, 'k': 0, 'l': 0,
                       'm': 0, 'n': 0, 'o': 0, 'p': 0, 'q': 0, 'r': 0, 's': 0, 't': 0, 'u': 0, 'v': 0, 'w': 0, 'x': 0,
                       'y': 0, 'z': 0}
        
        for letter in lower_text:
            occurrences[letter] += 1
            
        return occurrences
    
    def get_letter_frequencies(self, text: str) -> dict[str, float]:
        occurrences = self.get_letter_occurences(text)
        total_letters = sum(occurrences.values())
        frequencies = {letter: occurrences[letter] / total_letters for letter in occurrences}
        return frequencies

    def get_text_ressamblance(self, text: str) -> float:
        frequencies = self.get_letter_frequencies(text)
        ressamblance = sum(abs(frequencies[letter] - Vigenere.ENGLISH_FREQUENCIES[letter]) for letter in frequencies)
        return ressamblance
        
    def solve_key(self, min_key_size: int, max_key_size: int) -> str:
        best_keys = []
        text_letters = [letter for letter in self.encrypted_text.lower() if letter in string.ascii_lowercase]

        # Tester différentes longueurs de clé
        for key_length in range(min_key_size, max_key_size):
            key = [None] * key_length
            
            for key_index in range(key_length):
                # Extraction des lettres correspondant au même décalage dans la clé
                letters = "".join(itertools.islice(text_letters, key_index, None, key_length))
                shifts: list[dict[str: float]] = []
                
                # Tester chaque lettre de l'alphabet comme possible caractère de clé
                for key_char in string.ascii_lowercase:
                    shifts.append({key_char: self.get_text_ressamblance(Decrypt.vigenere(letters, key_char))})
                
                # Sélectionner la lettre minimisant l'écart de fréquence
                min_value = float('inf')
                min_key = None
                
                for shift in shifts:
                    for letter, freq in shift.items():
                        if freq < min_value:
                            min_value = freq
                            min_key = letter

                key[key_index] = min_key
            
            best_keys.append("".join(key))
        
        # Sélectionner la meilleure clé trouvée en minimisant l'écart de fréquence
        key_successes: dict[str, float] = {}
        for key in best_keys:
            success = self.get_text_ressamblance(Decrypt.vigenere(self.encrypted_text, key))
            key_successes[key] = success
            
        best_keys.sort(key=lambda key: key_successes[key])
        return best_keys
        
    def run(self, min_key_size: int, max_key_size: int):
        os.system("cls")
        print("[*] Running Vigenere...")
        print("============================================")
        keys = self.solve_key(min_key_size, max_key_size)
        print(Decrypt.vigenere(encrypted_text, keys[0]))
        print("============================================")
        print(f"[+] Key found: '{keys[0]}'")
    
if __name__ == "__main__":
    encrypted_text = """
        Iy qll autr o rzy etuqt vyu uh bexng nvlej pwn glrvvbaegca...
        Ah alwze y'ysk iiie nfrtxrv dcjuoru'kci, n'cgg vurkrct junj oms umietuuo.
        << Vkatxach : Cn lbcykmcvqb axlekh xofp qeoge zqnoxgaklyup >>, << Yfekmtrwqot x'ue
        kicvcf
        nvlej om polakdoe o'sbr hunhxm >>...
        Sgnaeha gzqgry, nolv tey gedha.
        Mlgg iuos, udvs bitih xsjavbrigzh le iiskxue epcvy jivfms kn vfwze nmbficeefm tkwhertorgehk
        xej dvnkys 50, rymz-gmif ah jfxz pkhsv d zeryfqkl lv pwnjy amhk lpq mrar d'lq paieei ?
        Qm vzsg rzys-mrcs pumrla dpkoajy cv tci r'uvrlb flgh nmcr vw yukflvv nocasf r'uvrlmnz
        unzpm ?
        Jp qivy on ydkkkl, eewzek boay goe pwnjy...
        Mfq uoybs, vr wodpmniy amhk l'pacyk... De jxqs vfuj hdetjzr woe cd xlajaiw led yigxys
        vqnatns vw ted liyrctvv yu'uh nfxa eyqsvmhe d'hvnaceew...
        Aaeybry aadlvs, iy sfqb tzsg ykm mvpms.
        Py slla af acyrygv rc aa fythm. J'lg spuotv oms vlowhaspsff krpclyukl pfxz ll
        oivttivpm fucs trumplh ekxuzum uty fidkttmb.
        W'gc bzhv cugpila. "Nzl Azk Xusrqs, py n'rl xad kcazle drv txuvrlt. Jp j'ov luik giny ga
        khbe”.
        Dyhnty gfvae. Of a thztlgbrsynk fwpoy. Cv vwne rchy fej pmmkm.
        J'rl natr iak xetrcvkltv dcjzsfq'noi. A'dq txiumh cn zprvtutvxz.
        Azneega uyc avtotv, f'msz wofo. Ka qywg iy qlh re byuo. Vq cl dovz onv hzrkor, t'hat ayfpk
        kuv mm
        mk muzv xlllhr.
        Vus gdzck ku'zo ve x'ywzk jaj...
        Qq pglcv tc'iw qs fkht dhvaiy pru uot...
        Lw cglcv tc'ir jeevm qfc xr yoij xv pknik piltl...
        Bv vurth yu'of n'rlue ayg rtmezjvex yt hx'ql yc rrblazw xay ytih ta...
        Dyhnty gfvae. Ziuk fm qf'gz sgct t'hat piuvu. Ke dmbg ziuj oms symvv.
        Mt n'cgg gfoiv yuk wa ruzigc. Iak joiwm s'uovih...
        Ted gacafszrvs kfetwzoygehkm dvimrrynk vcr wy zvmhe khtevboelyup aczsy l'yhzoohe
        udvs wcg ikcnvv l'ut xrfjce.
        Amie zlolymr junj xv Fzpiz ry rvicgk woewze wy ggajiulbe wooklliplbr.
        “I'ysk fi... C'kmt zfq qfc xr jiij hbrk...”
        Ccz, mm czlbnom tfxb lk goegm... Mpks fo de e'dq jggazv zeyacazle ghzsuhnv. Mm np jshx
        ui
        aduaom prute, pr xr t'ynkhvdxui ghct-prfr vfuj sirryr u'hcx fl xbal... Jv ywuy woeqiid rchy.
        Makdve misjh. Mnnmfr vynux iu zylvspoyc. Qr yink wwuy fej pmmpq.
        O y'kwoch, wn tiuj d loyls qkm pfwa dk vesh ilzpg da'in ryiiz fej fzonq dbal ue vbege...
        Lvv uocasnar dv yqatxe hxm vzsg nbyz slmn biucx vofq hrtxrv hbaoynk sze-xyqukm ek viny
        aolw.
        Wn l chr jimzqm pgl dvv aaogehkm ol lonule gdz dpq ocgnhztcey.
        Fej vmuwq eho uvrlmnz xej fpodcg n tiuj dxpxynuum tcmiikleew mn tiuj gms pjsikm dv ewnty
        vfownec, anom cvxf-co ytrlmne aczsy dvv ooantvv l'els rntm lv gmsklt.
        T'hat ymhek goegm mgcnkhvayr... Zr sinuh le r'ylvfbrzl sg jys trumanakhcrd, jo okuukh lu
        huuu. Qwud shvrcsfqa ut meiyqcp bswg yxzvbatn, srqa plwse iy qll xoalrrlb eeps ouh mrukhk
        mi th
        v'eeywg vus xhze vur uha pcmtvzyuiv ivoxej, hb c'pqh auos hxm vuos rsxewcn pxcmzqmly.
        Holv mxajceuhs... vw doam nfxa aansykt ciluitylj.
        Qwud pspnyrtkwny fa trvnlggfghcv... hb vuos ercs lndrryz tuqmohecv.
        Vofq skomtfqa sghs trclpsf qk jerx, aatm nrwqoyyzvzy, srqa duamv umltewrar... ek ywuy
        holv ipaczrf wrzpqnkfs.
        Mrcs nmbfzluzvmz jys srubpq ogugihxms, biuj iqnllqrf fej jcexlej, ywud ygfgmszqmz kn
        tilkhpx, jbam mrqqpafeq hb vzsg auos dhvtkt ee haslwoaz xe ercs luiih krzgfr woe t'hat viui
        qwtcc deujrv eqet... yt grcreybg i'ysk qwuy kuz vwmxcg ykm ciluitylj.
        Rci, uc ghom ue fziscnvo. Uoy afvsy ejw keroi uh ta nsfvumikh.
        Uot wrzpm edr qrroi uh rumyr cha gplg fkfoe fm qa'clj smndcbg kn dzvmnz, jaj vmlzl zral
        agsirkhcv.
        Pwn npwzk ysk g'mtxy pcxa mljwa woe mrcs, woectce nfcfk kuv ywuy he dh xacbcatyrvc
        rasuij.
        Mm sfgg ht batnmr, kn cvfq edr abt gaelneyne.
        Mrcs amiikt aiumtkl ue lvdttwqa, gazv doam nv swugcn cgm tfxa nuos ruzeecf...
        Nvlej wwuz, holv aoxksf ziuj oms symvv.
        Bhp Ksazir    
        """
    Vigenere(encrypted_text).run(1, 19)
