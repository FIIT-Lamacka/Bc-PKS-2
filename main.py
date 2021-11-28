import time
import socket
import threading
import tkinter as tk
from tkinter import filedialog
from crc import CrcCalculator, Crc32
crc_calculator = CrcCalculator(Crc32.CRC32)
console_lock = threading.Lock()


class PacketDatabase:
    def __init__(self):
        self.comms = []


class Comm:
    def __init__(self, com_ip, com_port, file_name=None):
        self.ip = com_ip
        self.port = com_port
        self.packets = []
        self.name = file_name


class Packet:
    def __init__(self, flag=b'0000', order=b'000000', crc=b'00000000', data=None):
        self.flag = flag
        self.order = order
        self.crc = crc
        self.data = data

    def raw(self):
        string = self.flag + self.order + self.crc
        if self.data is not None:
            string += self.data
        return string


def create_packet_flag(syn=False, size=False, name=False, psh=False, done=False, binary=False, txt=False,
                       file=False, msg=False, nnod=False, nod=False):

    parameters = locals().values()
    final_flag = 0
    bit_iterator = 1
    for parameter in parameters:
        if parameter:
            final_flag += bit_iterator
        bit_iterator *= 2

    return "{0:0{1}x}".format(final_flag, 4).encode()

def decypher_packet_flag(flag_bytes):
    bit_value_iter = 65536

    flag_dict = {"NOD": False,"NNOD": False,"MSG": False,"FILE": False,"TXT": False,"BIN": False,"DONE": False,
                "PSH": False,"NAME": False,"SIZE": False,"SYN": False
                 }
    dict_keys = ["NOD", "NNOD", "MSG", "FILE", "TXT", "BIN", "DONE", "PSH", "NAME", "SIZE", "SYN"]
    keys_iter = 10-16

    flag = int(flag_bytes, 16)

    for i in range(17):
        if flag - bit_value_iter >= 0:
            flag = flag - bit_value_iter
            flag_dict[dict_keys[keys_iter]] = True
        keys_iter += 1
        bit_value_iter /= 2

    return flag_dict


def fragment_message(message: bytes) -> list:
    global fragment_size
    return [message[i:i + fragment_size] for i in range(0, len(message), fragment_size)]


def create_message_packets(fragments: list) -> list:
    packets = []
    i = 1

    header_flag = create_packet_flag(msg=True, size=True)
    packets.append(Packet(flag=header_flag))

    header_flag = create_packet_flag(psh=True, txt=True, msg=True)
    for fragment in fragments:
        checksum = "{0:0{1}x}".format(crc_calculator.calculate_checksum(fragment), 8).encode()
        new_packet = Packet(flag=header_flag, crc=checksum, data=fragment)
        new_packet.order = "{0:0{1}x}".format(i, 6).encode()
        i += 1
        packets.append(new_packet)

    packets[-1].flag = create_packet_flag(psh=True, txt=True, msg=True, done=True)
    packets[0].order = "{0:0{1}x}".format(len(packets), 6).encode()

    return packets


def create_file_packets(fragments: list, filename: str) -> list:
    packets = []
    i = 1

    header_flag = create_packet_flag(file=True, size=True, name=True, txt=True)
    packets.append(Packet(flag=header_flag))

    header_flag = create_packet_flag(psh=True, binary=True, file=True)
    for fragment in fragments:
        checksum = "{0:0{1}x}".format(crc_calculator.calculate_checksum(fragment), 8).encode()
        new_packet = Packet(flag=header_flag, crc=checksum, data=fragment)
        new_packet.order = "{0:0{1}x}".format(i, 6).encode()
        i += 1
        packets.append(new_packet)

    packets[-1].flag = create_packet_flag(psh=True, binary=True, file=True, done=True)
    packets[0].order = "{0:0{1}x}".format(len(packets), 6).encode()
    packets[0].data = filename.encode()

    return packets

def assemble_packets(com_to_assemble: Comm):
    packets = com_to_assemble.packets
    flags = decypher_packet_flag(packets[0][:4])
    message = b''
    if flags["MSG"]:
        for packet in packets[1:]:
            message += packet[18:]
        console_lock.acquire()
        print("(", com_to_assemble.ip,",", str(com_to_assemble.port), ")", message.decode("UTF-8"))
        console_lock.release()
    if flags["FILE"]:
        f = open(com_to_assemble.name, "ab")
        for packet in packets[1:]:
            f.write(packet[18:])
        f.close()
        print("File transfer DONE!")




def assembler(given_data, given_addr):
    global packet_database

    flags = decypher_packet_flag(given_data[:4])


    if flags["SIZE"] and flags["MSG"]:
        new_com = Comm(given_addr[0], given_addr[1])
        new_com.packets.append(given_data)
        packet_database.comms.append(new_com)
    elif flags["MSG"]:
        for com in packet_database.comms:
            if com.ip == given_addr[0] and com.port == given_addr[1]:
                com.packets.append(given_data)
            if flags["DONE"]:
                assemble_packets(com)
                packet_database.comms.remove(com)
            break
    elif flags["FILE"] and flags["SIZE"]:
        new_com = Comm(given_addr[0], given_addr[1], file_name=given_data[18:])
        new_com.packets.append(given_data)
        packet_database.comms.append(new_com)
    elif flags["FILE"]:
        for com in packet_database.comms:
            if com.ip == given_addr[0] and com.port == given_addr[1]:
                com.packets.append(given_data)
            if flags["DONE"]:
                assemble_packets(com)
                packet_database.comms.remove(com)
            break


def recieve_mode():
    global ip, port, sock
    while True:
        data, addr = sock.recvfrom(1550)  # buffer size is 1024 bytes
        console_lock.acquire()
        #print(addr, data)
        console_lock.release()

        ass = threading.Thread(target=assembler, args=(data, addr), daemon=True)
        ass.start()


def send_msg(args):
    arguments = args.split(" ", maxsplit=2)
    console_lock.acquire()
    print("SENDING MESSAGE TO" , arguments[0], " PORT:", arguments[1], " MESSAGE: ", arguments[2])
    console_lock.release()
    global sock

    msg_frag = fragment_message(arguments[2].encode())
    msg_frag = create_message_packets(msg_frag)
    for frag in msg_frag:
        sock.sendto(frag.raw(), (arguments[0], int(arguments[1])))


def send_file(args):
    arguments = args.split(" ", maxsplit=2)

    root = tk.Tk()
    root.withdraw()

    file_path = filedialog.askopenfilename()

    with open(file_path, "rb") as file:
        byte = file.read()
        file_fragments = fragment_message(byte)

    print("File loaded succesfuly....")
    filename = file_path.split("/")[-1]
    print("Fragmenting file...")
    file_frag = create_file_packets(file_fragments, filename)
    print("Sending file...")
    for frag in file_frag:
        sock.sendto(frag.raw(), (arguments[0], int(arguments[1])))
        time.sleep(0.0001)
    print("FILE SENT SUCCESFULLY!")

def listen():
    pass


def hub():


    listener = threading.Thread(target=recieve_mode, args=(), daemon=True)
    listener.stopped = False
    listener.start()
    time.sleep(0.2)

    while True:
        global ip, port, mode
        command = input("INPUT COMMANDS:\n").split(" ", maxsplit=1)

        if command[0].lower() == "socket" or command[0].lower() == "s":
            socket = command[1].split(" ")
            ip = socket[0]
            port = socket[1]
            print("SOCKET HAS CHANGED TO", ip, "PORT", port)

        if command[0].lower() == "fragment" or command[0].lower() == "fr":
            global fragment_size
            if len(command) > 1:
                selected_size = command[1]
                while int(selected_size) < 1 or int(selected_size) > 1472:
                    selected_size = int(input("Zadajte veľkosť fragmentu od 1B po 1472B: "))
                fragment_size = int(selected_size)
            else:
                selected_size = 1500
                while selected_size < 1 or selected_size > 1472:
                    selected_size = int(input("Zadajte veľkosť fragmentu od 1B po 1472B: "))
                fragment_size = selected_size
            print("FRAGMENT SIZE IS SET TO ", fragment_size)

        if command[0].lower() == "file" or command[0].lower() == "f":
            send_file(command[1])

        if command[0].lower() == "message" or command[0].lower() == "m":
            send_msg(command[1])


if __name__ == '__main__':
    mode = "receive"
    fragment_size = 1472
    ip = "127.0.0.1"
    port = input("SET PORT: ")


    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ip, int(port)))
    packet_database = PacketDatabase()

    hub()
    # alicemessage = "Chapter One – Down the Rabbit Hole: Alice, a seven-year-old girl, is feeling bored and drowsy while sitting on the riverbank with her elder sister. She notices a talking, clothed white rabbit with a pocket watch run past. She follows it down a rabbit hole where she suddenly falls a long way to a curious hall with many locked doors of all sizes. She finds a little key to a door too small for her to fit through, but through it, she sees an attractive garden. She then discovers a bottle on a table labelled DRINK ME, the contents of which cause her to shrink too small to reach the key which she had left on the table. She subsequently eats a cake labelled  in currants as the chapter closes.Chapter Two – The Pool of Tears: The chapter opens with Alice growing to such a tremendous size that her head hits the ceiling. Unhappy, Alice begins to cry and her tears literally flood the hallway. After she picks up a fan that causes her to shrink back down, Alice swims through her own tears and meets a mouse, who is swimming as well. Alice, thinking he may be a French mouse, tries to make small talk with him in elementary French. Her opening gambit Où est ma chatte? (transl.Where is my cat?), however, offends the mouse, who then tries to escape her.Chapter Three – The Caucus Race and a Long Tale: The sea of tears becomes crowded with other animals and birds that have been swept away by the rising waters. Alice and the other animals convene on the bank and the question among them is how to get dry again. Mouse gives them a very dry lecture on William the Conqueror. A dodo decides that the best thing to dry them off would be a Caucus-Race, which consists of everyone running in a circle with no clear winner. Alice eventually frightens all the animals away, unwittingly, by talking about her (moderately ferocious) cat.Chapter Four – The Rabbit Sends a Little Bill: White Rabbit appears again in search of the Duchess's gloves and fan. Mistaking her for his maidservant, Mary Ann, Rabbit orders Alice to go into the house and retrieve them. Inside the house she finds another little bottle and drinks from it, immediately beginning to grow again. The horrified Rabbit orders his gardener, Bill the Lizard, to climb on the roof and go down the chimney. Outside, Alice hears the voices of animals that have gathered to gawk at her giant arm. The crowd hurls pebbles at her, which turn into little cakes. Alice eats them, and they reduce her again in size.Chapter Five – Advice from a Caterpillar: Alice comes upon a mushroom and sitting on it is a blue caterpillar smoking a hookah. Caterpillar questions Alice, who begins to admit to her current identity crisis, compounded by her inability to remember a poem. Before crawling away, the caterpillar tells Alice that one side of the mushroom will make her taller and the other side will make her shorter. She breaks off two pieces from the mushroom. One side makes her shrink smaller than ever, while another causes her neck to grow high into the trees, where a pigeon mistakes her for a serpent. With some effort, Alice brings herself back to her normal height. She stumbles upon a small estate and uses the mushroom to reach a more appropriate height. "


