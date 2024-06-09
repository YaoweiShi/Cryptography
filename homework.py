# 可视化界面
from tkinter import *
import tkinter as tk
from tkinter import font


def decrypt():
    ciphertext = ciphertextbox.get("1.0", tk.END).strip()
    key = keybox.get("1.0", tk.END).strip()

    ciphertexts = []
    keys = []

    for p in ciphertext:
        ciphertexts.append(p)

    for k in key:
        k = k.lower()
        keys.append(k)

    plaintexts = []

    for i in range(len(ciphertexts)):
        c = ciphertexts[i]
        if ord("a") <= ord(ciphertexts[i]) <= ord("z"):
            c = keys.index(ciphertexts[i])
            c = chr(c + ord("a"))
        if ord("A") <= ord(ciphertexts[i]) <= ord("Z"):
            c = keys.index(ciphertexts[i].lower())
            c = chr(c + ord("A"))
        plaintexts.append(c)

    plaintexts = "".join(plaintexts)
    plaintextbox.delete("1.0", tk.END)
    plaintextbox.insert(tk.END, plaintexts)


def encrypt():
    plaintext = plaintextbox.get("1.0", tk.END).strip()
    key = keybox.get("1.0", tk.END).strip()

    plaintexts = []
    keys = []

    for p in plaintext:
        plaintexts.append(p)

    for k in key:
        k = k.lower()
        keys.append(k)

    ciphertexts = []

    for i in range(len(plaintexts)):
        c = plaintexts[i]
        if ord("a") <= ord(plaintexts[i]) <= ord("z"):
            c = ord(plaintexts[i])
            c = keys[c - ord("a")]
        if ord("A") <= ord(plaintexts[i]) <= ord("Z"):
            c = ord(plaintexts[i])
            c = keys[c - ord("A")]
            c = c.upper()
        ciphertexts.append(c)

    ciphertexts = "".join(ciphertexts)
    ciphertextbox.delete("1.0", tk.END)
    ciphertextbox.insert(tk.END, ciphertexts)


def findkey(c):
    for i in range(26):
        if newkey[i] == c:
            return i
    return -1


def addkey():
    lettercipher = letterciphertext.get("1.0", tk.END).strip()
    letterplain = letterplaintext.get("1.0", tk.END).strip()
    if 0 <= (ord(letterplain.upper()) - ord("A")) <= 25:
        if 0 <= (ord(lettercipher.upper()) - ord("A")) <= 25:
            newkey[ord(letterplain.upper()) - ord("A")] = lettercipher.upper()
    newkeytexts = "".join(newkey)
    newkeylb.config(text="目前密钥为：" + newkeytexts)


def deletekey():
    lettercipher = letterciphertext.get("1.0", tk.END).strip()
    if findkey(lettercipher.upper()) != -1:
        newkey[findkey(lettercipher)] = "?"
    newkeytexts = "".join(newkey)
    newkeylb.config(text="目前密钥为：" + newkeytexts)


def suggest():
    ciphertext = ciphertextbox.get("1.0", tk.END).strip()

    ciphertexts = []
    keys = newkey

    frequency = [0 for i in range(26)]
    frequency_two = [0 for i in range(26 * 26)]
    frequency_double = [0 for i in range(26)]
    alphabet = []
    alphabet_two = []
    alphabet_double = []

    for p in ciphertext:
        if ord("A") <= ord(p) <= ord("Z") or ord("a") <= ord(p) <= ord("z"):
            p = p.lower()
            frequency[ord(p) - ord("a")] += 1
        ciphertexts.append(p)

    for i in range(len(ciphertexts) - 1):
        if ord("a") <= ord(ciphertexts[i]) <= ord("z") and ord("a") <= ord(
            ciphertexts[i + 1]
        ) <= ord("z"):
            frequency_two[
                (ord(ciphertexts[i]) - ord("a")) * 26
                + (ord(ciphertexts[i + 1]) - ord("a"))
            ] += 1

    for i in range(26):
        c = chr(i + ord("a"))
        alphabet.append(c)

    for i in range(26):
        for j in range(26):
            c1 = chr(i + ord("a"))
            c2 = chr(j + ord("a"))
            c = c1 + c2
            alphabet_two.append(c)

    for i in range(26):
        frequency_double[i] = frequency_two[i * 26 + i]
        alphabet_double.append(alphabet_two[i * 26 + i])

    for i in range(25):
        for j in range(26 - i - 1):
            if frequency[j] < frequency[j + 1]:
                tempf = frequency[j]
                frequency[j] = frequency[j + 1]
                frequency[j + 1] = tempf
                tempa = alphabet[j]
                alphabet[j] = alphabet[j + 1]
                alphabet[j + 1] = tempa

    for i in range(26 * 26 - 1):
        for j in range(26 * 26 - i - 1):
            if frequency_two[j] < frequency_two[j + 1]:
                tempf = frequency_two[j]
                frequency_two[j] = frequency_two[j + 1]
                frequency_two[j + 1] = tempf
                tempa = alphabet_two[j]
                alphabet_two[j] = alphabet_two[j + 1]
                alphabet_two[j + 1] = tempa

    for i in range(25):
        for j in range(26 - i - 1):
            if frequency_double[j] < frequency_double[j + 1]:
                tempf = frequency_double[j]
                frequency_double[j] = frequency_double[j + 1]
                frequency_double[j + 1] = tempf
                tempa = alphabet_double[j]
                alphabet_double[j] = alphabet_double[j + 1]
                alphabet_double[j + 1] = tempa

    s1 = (
        "频率排名前三的密文字母"
        + alphabet[0]
        + ","
        + alphabet[1]
        + ","
        + alphabet[2]
        + "很可能对应字母e,t,a."
    )

    s2 = (
        "频率排名前三的两字母密文组合"
        + alphabet_two[0]
        + ","
        + alphabet_two[1]
        + ","
        + alphabet_two[2]
        + "很可能对应字母组合th,he,an."
    )

    s3 = (
        "频率排名前三的两相同字母密文组合"
        + alphabet_double[0]
        + ","
        + alphabet_double[1]
        + ","
        + alphabet_double[2]
        + "很可能对应两相同字母组合ll,ee,ss."
    )

    plaintextbox.delete("1.0", tk.END)
    plaintextbox.insert(tk.END, "****解密建议****")
    plaintextbox.insert(tk.END, "\n")
    plaintextbox.insert(tk.END, s1)
    plaintextbox.insert(tk.END, "\n")
    plaintextbox.insert(tk.END, s2)
    plaintextbox.insert(tk.END, "\n")
    plaintextbox.insert(tk.END, s3)
    plaintextbox.insert(tk.END, "\n")
    plaintextbox.insert(tk.END, "****目前明文****")
    plaintextbox.insert(tk.END, "\n")

    for i in range(len(ciphertexts)):
        c = ciphertexts[i]
        if (ord("a") <= ord(c) <= ord("z")) and (
            0 <= findkey(ciphertexts[i].upper()) <= 25
        ):
            c = findkey(ciphertexts[i].upper())
            c = chr(c + ord("a"))
            plaintextbox.insert(tk.END, c, "red")
        else:
            if (ord("A") <= ord(c) <= ord("Z")) and (
                0 <= findkey(ciphertexts[i]) <= 25
            ):
                c = findkey(ciphertexts[i])
                c = chr(c + ord("a"))
                plaintextbox.insert(tk.END, c.upper(), "red")
            else:
                plaintextbox.insert(tk.END, c)

    newkeytexts = "".join(newkey)
    newkeylb.config(text="目前密钥为：" + newkeytexts)


root = Tk()
root.geometry("1000x800")
root.title("密码学导论大作业：单表代换辅助工具")

custom_font = font.Font(family="微软雅黑", size=12)
bottom_font = font.Font(family="微软雅黑", size=16)

lb1 = Label(
    root,
    text="单表代换辅助工具",
    fg="#006060",
    font=("微软雅黑", 24),
    width=20,
    height=2,
)
lb1.place(relx=0.1, rely=0.04, relwidth=0.8, relheight=0.1)

lb2L = Label(
    root,
    text="密文",
    fg="#000000",
    font=("微软雅黑", 16),
)
lb2L.place(relx=0.07, rely=0.12, relwidth=0.4, relheight=0.1)

lb2R = Label(
    root,
    text="明文",
    fg="#000000",
    font=("微软雅黑", 16),
)
lb2R.place(relx=0.53, rely=0.12, relwidth=0.4, relheight=0.1)

ciphertextbox = tk.Text(root, wrap=tk.WORD, font=custom_font)
ciphertextbox.place(relx=0.07, rely=0.2, relwidth=0.4, relheight=0.4)
plaintextbox = tk.Text(root, wrap=tk.WORD, font=custom_font)
plaintextbox.place(relx=0.53, rely=0.2, relwidth=0.4, relheight=0.4)

plaintextbox.tag_configure("red", foreground="red")

lb3L = Label(
    root,
    text="密钥：26个字母的一个排列",
    fg="#000000",
    font=("微软雅黑", 16),
)
lb3L.place(relx=0.07, rely=0.62, relwidth=0.4, relheight=0.1)

keybox = tk.Text(root, wrap=tk.WORD, font=custom_font)
keybox.place(relx=0.07, rely=0.71, relwidth=0.4, relheight=0.03)

btn1 = Button(root, text="解密", command=decrypt, font=bottom_font)
btn1.place(relx=0.13, rely=0.785, relwidth=0.12, relheight=0.04)

btn2 = Button(root, text="加密", command=encrypt, font=bottom_font)
btn2.place(relx=0.29, rely=0.785, relwidth=0.12, relheight=0.04)

newkey = []

for i in range(26):
    newkey.append("?")

btn3 = Button(root, text="解密建议", command=suggest, font=bottom_font)
btn3.place(relx=0.64, rely=0.645, relwidth=0.18, relheight=0.04)

lb3R = Label(
    root,
    text="密文字母",
    fg="#000000",
    font=("微软雅黑", 12),
)
lb3R.place(relx=0.53, rely=0.7, relwidth=0.08, relheight=0.05)

letterciphertext = tk.Text(root, wrap=tk.WORD, font=custom_font)
letterciphertext.place(relx=0.61, rely=0.71, relwidth=0.02, relheight=0.03)

lb4R = Label(
    root,
    text="明文字母",
    fg="#000000",
    font=("微软雅黑", 12),
)
lb4R.place(relx=0.65, rely=0.7, relwidth=0.08, relheight=0.05)

letterplaintext = tk.Text(root, wrap=tk.WORD, font=custom_font)
letterplaintext.place(relx=0.73, rely=0.71, relwidth=0.02, relheight=0.03)

btn4 = Button(root, text="更新", command=addkey, font=bottom_font)
btn4.place(relx=0.79, rely=0.705, relwidth=0.06, relheight=0.04)

btn5 = Button(root, text="撤回", command=deletekey, font=bottom_font)
btn5.place(relx=0.87, rely=0.705, relwidth=0.06, relheight=0.04)

newkeylb = tk.Label(root, text="", font=custom_font)
newkeylb.place(relx=0.53, rely=0.79, relwidth=0.4, relheight=0.03)

# # 方法二利用 lambda 传参数调用run2()
# btn2 = Button(root, text="方法二", command=lambda: run2(inp1.get(), inp2.get()))
# btn2.place(relx=0.6, rely=0.4, relwidth=0.3, relheight=0.1)

# # 在窗体垂直自上而下位置60%处起，布局相对窗体高度40%高的文本框
# txt = Text(root)
# txt.place(rely=0.6, relheight=0.4)

root.mainloop()