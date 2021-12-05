import time
import socket
import threading
import random
from colorama import *
import zlib
import tkinter as tk
from tkinter import filedialog
from crc import CrcCalculator, Crc32

crc_calculator = CrcCalculator(Crc32.CRC32, True)
console_lock = threading.Lock()
socket_lock = threading.Lock()
hello_lock = threading.Lock()
ack_lock = threading.Lock()

send_event = threading.Event()
packet_change_event = threading.Event()

connections = []
last_packet = None
last_socket = ("0", 0)
last_flags = {"NOD": False, "NNOD": False, "MSG": False, "FILE": False, "TXT": False, "BIN": False, "DONE": False,
              "PSH": False, "NAME": False, "SIZE": False, "SYN": False}
make_errors = False

save_location = ""
init()


class PacketDatabase:
    def __init__(self):
        self.comms = []


class Connection:
    def __init__(self):
        self.ip = None
        self.port = None
        self.last_hello_time = 0


class Comm:
    def __init__(self, com_ip, com_port, file_name=None):
        self.ip = com_ip
        self.port = com_port
        self.packets = []
        self.name = file_name


class Packet:
    def __init__(self, flag=b'\x00\x00', order=b'\x00\x00\x00', crc=b'\x00\x00\x00\x00', data=None):
        self.flag = flag
        self.order = order
        self.crc = crc
        self.data = data

    def raw(self):
        global make_errors
        error_if_zero = random.randint(0, 16)
        string = self.flag + self.order + self.crc

        if self.data is not None and not make_errors:
            string += self.data
        elif self.data is not None and make_errors and error_if_zero == 0:
            bad_data = self.data
            error_at = random.randint(0, len(bad_data)-1)
            string += bad_data[:error_at] + b'0' + bad_data[error_at:]
        elif self.data is not None and make_errors:
            string += self.data

        return string


def locked_print(*args, **kwargs):
    global console_lock

    console_lock.acquire()
    print(" ".join(map(str, args)), **kwargs)
    console_lock.release()


# ZDROJ: Greenstick - https://stackoverflow.com/questions/3173320/text-progress-bar-in-the-console
def print_progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='█', print_end="\r"):

    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '░' * (length - filled_length)
    print(f'\r\t{prefix}|{bar}| {percent}% {suffix}', end=print_end)
    # Print New Line on Complete
    if iteration == total:
        print()


def create_packet_flag(syn=False, size=False, name=False, psh=False, done=False, binary=False, txt=False,
                       file=False, msg=False, nnod=False, nod=False):

    parameters = locals().values()
    final_flag = 0
    bit_iterator = 1
    for parameter in parameters:
        if parameter:
            final_flag += bit_iterator
        bit_iterator *= 2

    # return "{0:0{1}x}".format(final_flag, 4).encode()
    return final_flag.to_bytes(2, byteorder="big")


def decypher_packet_flag(flag_bytes):

    bit_value_iter = 65536
    flag_dict = {"NOD": False, "NNOD": False, "MSG": False, "FILE": False, "TXT": False, "BIN": False, "DONE": False,
                 "PSH": False, "NAME": False, "SIZE": False, "SYN": False
                 }
    dict_keys = ["NOD", "NNOD", "MSG", "FILE", "TXT", "BIN", "DONE", "PSH", "NAME", "SIZE", "SYN"]
    keys_iter = 10-16

    flag = int.from_bytes(flag_bytes, byteorder="big")

    for i in range(17):
        if flag - bit_value_iter >= 0:
            flag = flag - bit_value_iter
            flag_dict[dict_keys[keys_iter]] = True
        keys_iter += 1
        bit_value_iter /= 2

    return flag_dict


def fragment_data(message: bytes) -> list:

    global fragment_size
    return [message[i:i + fragment_size] for i in range(0, len(message), fragment_size)]


def create_message_packets(fragments: list) -> list:

    packets = []
    i = 1

    packet_flags = create_packet_flag(msg=True, size=True)
    packets.append(Packet(flag=packet_flags))

    packet_flags = create_packet_flag(psh=True, txt=True, msg=True)
    for fragment in fragments:
        checksum = zlib.crc32(fragment).to_bytes(4, byteorder="big")
        new_packet = Packet(flag=packet_flags, crc=checksum, data=fragment)
        new_packet.order = i.to_bytes(3, byteorder="big")
        i += 1
        packets.append(new_packet)

    packets[-1].flag = create_packet_flag(psh=True, txt=True, msg=True, done=True)
    packets[0].order = len(packets).to_bytes(3, byteorder="big")

    return packets


def create_file_packets(fragments: list, filename: str) -> list:

    packets = []
    i = 1

    header_flag = create_packet_flag(file=True, size=True, name=True, txt=True)
    packets.append(Packet(flag=header_flag))

    header_flag = create_packet_flag(psh=True, binary=True, file=True)
    for fragment in fragments:
        checksum = zlib.crc32(fragment).to_bytes(4, byteorder="big")
        new_packet = Packet(flag=header_flag, crc=checksum, data=fragment)
        new_packet.order = i.to_bytes(3, byteorder="big")
        i += 1
        packets.append(new_packet)

    packets[-1].flag = create_packet_flag(psh=True, binary=True, file=True, done=True)
    packets[0].order = len(packets).to_bytes(3, byteorder="big")
    packets[0].data = filename.encode()

    return packets


def assemble_packets(com_to_assemble: Comm):

    assembled_packets = com_to_assemble.packets
    flags = decypher_packet_flag(assembled_packets[0][:2])
    message = b''
    if flags["MSG"]:
        for packet in assembled_packets[1:]:
            message += packet[9:]

        locked_print("(", com_to_assemble.ip, ",", str(com_to_assemble.port), ")", message.decode("UTF-8"))

    if flags["FILE"]:
        f = open(save_location + com_to_assemble.name.decode("utf-8"), "ab")
        for packet in assembled_packets[1:]:
            f.write(packet[9:])
        f.close()
        locked_print(Fore.GREEN + "File transfer done! \n File saved to" + save_location + Style.RESET_ALL)


def assembler(given_data, given_addr):

    global packet_database, sock, last_packet, last_socket, last_flags

    flags = decypher_packet_flag(given_data[:2])
    last_flags = flags
    last_packet = given_data
    last_socket = given_addr

    if flags["SYN"] and flags["NOD"]:
        global connections
        syn_packet = Packet(flag=create_packet_flag(syn=True))
        sock.sendto(syn_packet.raw(), given_addr)

        new_con = Connection()
        new_con.ip = given_addr[0]
        new_con.port = given_addr[1]
        connections.append(new_con)
        packet_change_event.set()
        return

    if flags["SYN"] and flags["NNOD"]:
        locked_print("Recieved HELLO from", given_addr[0], given_addr[1])

        update = threading.Thread(target=connection_update, args=(given_addr[0], given_addr[1]), daemon=True)
        update.start()
        packet_change_event.set()
        return

    if flags["PSH"]:
        local_crc = zlib.crc32(given_data[9:]).to_bytes(4, byteorder="big")
        sender_crc = given_data[5:9]
        if local_crc == sender_crc:
            ack_packet = Packet(flag=create_packet_flag(nod=True))
            sock.sendto(ack_packet.raw(), given_addr)
            locked_print("Received packet", int.from_bytes(given_data[2:5], byteorder="big"), "of size",
                         len(given_data[9:]), "[", Fore.GREEN, "OK", Style.RESET_ALL, "]")

        else:
            nack_packet = Packet(flag=create_packet_flag(nnod=True))
            sock.sendto(nack_packet.raw(), given_addr)
            locked_print("Received packet", int.from_bytes(given_data[2:5], byteorder="big"), "of size",
                         len(given_data[9:]), "[", Fore.RED, "ERROR", Style.RESET_ALL, "]")
            packet_change_event.set()
            return

    if flags["SIZE"] and flags["MSG"]:
        send_event.clear()
        ack_packet = Packet(flag=create_packet_flag(nod=True))
        sock.sendto(ack_packet.raw(), given_addr)

        new_com = Comm(given_addr[0], given_addr[1])
        new_com.packets.append(given_data)
        packet_database.comms.append(new_com)
    elif flags["MSG"]:
        for com in packet_database.comms:
            if com.ip == given_addr[0] and com.port == given_addr[1]:
                com.packets.append(given_data)
            if flags["DONE"]:
                send_event.set()
                assemble_packets(com)
                packet_database.comms.remove(com)
            break

    elif flags["FILE"] and flags["SIZE"]:
        send_event.clear()
        ack_packet = Packet(flag=create_packet_flag(nod=True))
        sock.sendto(ack_packet.raw(), given_addr)

        new_com = Comm(given_addr[0], given_addr[1], file_name=given_data[9:])
        new_com.packets.append(given_data)
        packet_database.comms.append(new_com)
    elif flags["FILE"]:
        for com in packet_database.comms:
            if com.ip == given_addr[0] and com.port == given_addr[1]:
                com.packets.append(given_data)
            if flags["DONE"]:
                send_event.set()
                assemble_packets(com)
                packet_database.comms.remove(com)
            break
    packet_change_event.set()


def recieve_mode():

    global ip, port, sock
    while True:
        try:
            data, addr = sock.recvfrom(1550)  # buffer size is 1024 bytes
        except ConnectionResetError:

            console_lock.acquire()
            print(Fore.RED + "\nThe program has encountered a connection error, please restart the program!"
                  + Style.RESET_ALL)
            input()
            exit()
            return

        ass = threading.Thread(target=assembler, args=(data, addr), daemon=True)
        ass.start()


def create_connection(dest_ip, dest_port):

    for con in connections:
        if con.ip == dest_ip and con.port == dest_port:
            locked_print("Connection already established")
            return

    packet_flag = create_packet_flag(syn=True, nod=True)
    syn_packet = Packet(flag=packet_flag)

    packet_change_event.clear()
    sock.sendto(syn_packet.raw(), (dest_ip, dest_port))
    packet_change_event.wait()
    flags = decypher_packet_flag(last_packet[:2])
    packet_change_event.clear()

    while not flags["SYN"] and last_socket[0] == dest_ip and int(last_socket[1]) == dest_port:
        packet_change_event.wait()
        flags = decypher_packet_flag(last_packet[:2])
        packet_change_event.clear()

    new_connection = Connection()
    new_connection.ip = dest_ip
    new_connection.port = dest_port
    new_connection.last_hello_time = 0
    locked_print("Created new connection!")
    connections.append(new_connection)


def connection_hello():
    global connections

    while True:
        time.sleep(5)
        send_event.wait()
        for conn in connections:
            hello_packet = Packet(flag=create_packet_flag(syn=True, nnod=True))
            sock.sendto(hello_packet.raw(), (conn.ip, conn.port))

            locked_print("Sending hello to:", conn.ip,  conn.port)


def connection_update(given_ip, given_port):

    global connections
    for con in connections:
        if con.ip == given_ip and con.port == given_port:
            con.last_hello_time = 0


def connection_killer():
    global connections

    while True:
        to_delete = []
        send_event.wait()
        time.sleep(1)
        for conn in connections:
            conn.last_hello_time += 1
            if conn.last_hello_time >= 10:
                locked_print(Fore.YELLOW + "No HELLO response from", conn.ip, conn.port, "terminating!"
                             + Style.RESET_ALL)
                to_delete.append(conn)

        for dead_connection in to_delete:
            connections.remove(dead_connection)


def end_connection(connection):

    global connections
    given_socket = connection.split(" ")

    for con in connections:
        if con.ip == given_socket[0] and con.port == int(given_socket[1]):
            locked_print("Removing " + connection + "connection!")
            connections.remove(con)
            return
    locked_print("Connection not found!")


def send_msg(args):

    global last_packet, sock
    arguments = args.split(" ", maxsplit=2)

    send_event.clear()
    time.sleep(0.5)
    packet_change_event.clear()

    locked_print("\tFragmenting message...")
    msg_frag = fragment_data(arguments[2].encode())
    msg_frag = create_message_packets(msg_frag)
    packet_no = 0
    total_packets_len = len(msg_frag)

    locked_print("\tEstablishing connection: ", end="")
    create_connection(arguments[0], int(arguments[1]))

    locked_print("\tSending message...")
    for frag in msg_frag:
        packet_no += 1

        sock.sendto(frag.raw(), (arguments[0], int(arguments[1])))

        packet_change_event.wait(timeout=2.0)
        flags = decypher_packet_flag(last_packet[:2])
        packet_change_event.clear()

        nnod_counter = 0
        while flags["NNOD"]:
            if nnod_counter == 3:

                locked_print(Fore.RED + "\tMESSAGE NOT SENT!" + Style.RESET_ALL)

                send_event.set()
                return

            nnod_counter += 1
            sock.sendto(frag.raw(), (arguments[0], int(arguments[1])))
            packet_change_event.wait(timeout=2.0)
            flags = decypher_packet_flag(last_packet[:2])
            packet_change_event.clear()
        console_lock.acquire()
        print_progress_bar(packet_no, total_packets_len)
        console_lock.release()

    locked_print(Fore.GREEN + "\n\tMESSAGE SENT SUCCESFULLY!" + Style.RESET_ALL)

    send_event.set()


def send_file(args):

    global last_packet
    arguments = args.split(" ", maxsplit=2)

    root = tk.Tk()
    root.withdraw()

    file_path = filedialog.askopenfilename()

    send_event.clear()
    time.sleep(0.5)
    packet_change_event.clear()

    with open(file_path, "rb") as file:
        byte = file.read()
        file_fragments = fragment_data(byte)

    locked_print(Fore.GREEN + "\tFile loaded succesfuly...." + Style.RESET_ALL)

    filename = file_path.split("/")[-1]

    locked_print("\tFragmenting file...")

    file_frag = create_file_packets(file_fragments, filename)
    packet_no = 0
    total_packets_len = len(file_frag)

    locked_print("\tEstablishing connection: ", end="")

    create_connection(arguments[0], int(arguments[1]))

    locked_print("\tSending file: ", file_path, "\n\t", len(file_frag), "packet(s) of", fragment_size, "bytes\n")

    for frag in file_frag:
        packet_no += 1
        sock.sendto(frag.raw(), (arguments[0], int(arguments[1])))
        packet_change_event.wait(timeout=2.0)
        flags = decypher_packet_flag(last_packet[:2])
        packet_change_event.clear()
        nnod_counter = 0
        while flags["NNOD"]:
            if nnod_counter == 3:
                locked_print(Fore.RED + "\tFILE NOT SENT!" + Style.RESET_ALL)
                send_event.set()
                return

            nnod_counter += 1
            sock.sendto(frag.raw(), (arguments[0], int(arguments[1])))
            packet_change_event.wait(timeout=2.0)
            flags = decypher_packet_flag(last_packet[:2])
            packet_change_event.clear()
        console_lock.acquire()
        print_progress_bar(packet_no, total_packets_len)
        console_lock.release()

    locked_print(Fore.GREEN + "\n\tFILE SENT SUCCESFULLY!" + Style.RESET_ALL)
    send_event.set()


def change_download_directory():
    global save_location

    root = tk.Tk()
    root.withdraw()
    save_location = filedialog.askdirectory() + "/"
    locked_print(Fore.GREEN + "NEW SAVE LOCATION: " + save_location + Style.RESET_ALL)


def user_interface():
    while True:
        global ip, port, mode
        locked_print(Fore.CYAN + "INPUT COMMANDS:\n" + Style.RESET_ALL)
        command = input("").split(" ", maxsplit=1)

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
            locked_print("FRAGMENT SIZE IS SET TO ", fragment_size)

        if command[0].lower() == "file" or command[0].lower() == "f":
            send_file(command[1])

        if command[0].lower() == "message" or command[0].lower() == "m":
            send_msg(command[1])

        if command[0].lower() == "end" or command[0].lower() == "c":
            end_connection(command[1])

        if command[0].lower() == "down" or command[0].lower() == "cd":
            change_download_directory()

        if command[0].lower() == "error" or command[0].lower() == "e":
            global make_errors
            if make_errors:
                make_errors = False
                locked_print("Errors have been turned off.")

            else:
                make_errors = True
                locked_print(Fore.YELLOW + "DELIBERATE ERRORS HAVE BEEN TURNED ON!" + Style.RESET_ALL)


def hub():

    listener = threading.Thread(target=recieve_mode, args=(), daemon=True)
    listener.stopped = False
    listener.start()
    hello = threading.Thread(target=connection_hello, args=(), daemon=True)
    hello.start()
    hello_killer = threading.Thread(target=connection_killer, args=(), daemon=True)
    hello_killer.start()
    time.sleep(0.2)

    user_interface()


if __name__ == '__main__':

    mode = "receive"
    fragment_size = 1472
    ip = "127.0.0.1"

    locked_print(Fore.CYAN + "SET PORT: " + Style.RESET_ALL, end="")
    port = input("")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ip, int(port)))
    packet_database = PacketDatabase()

    hub()
    # alicemessage = "Chapter One – Down the Rabbit Hole: Alice, a seven-year-old girl, is feeling bored and drowsy while sitting on the riverbank with her elder sister. She notices a talking, clothed white rabbit with a pocket watch run past. She follows it down a rabbit hole where she suddenly falls a long way to a curious hall with many locked doors of all sizes. She finds a little key to a door too small for her to fit through, but through it, she sees an attractive garden. She then discovers a bottle on a table labelled DRINK ME, the contents of which cause her to shrink too small to reach the key which she had left on the table. She subsequently eats a cake labelled  in currants as the chapter closes.Chapter Two – The Pool of Tears: The chapter opens with Alice growing to such a tremendous size that her head hits the ceiling. Unhappy, Alice begins to cry and her tears literally flood the hallway. After she picks up a fan that causes her to shrink back down, Alice swims through her own tears and meets a mouse, who is swimming as well. Alice, thinking he may be a French mouse, tries to make small talk with him in elementary French. Her opening gambit Où est ma chatte? (transl.Where is my cat?), however, offends the mouse, who then tries to escape her.Chapter Three – The Caucus Race and a Long Tale: The sea of tears becomes crowded with other animals and birds that have been swept away by the rising waters. Alice and the other animals convene on the bank and the question among them is how to get dry again. Mouse gives them a very dry lecture on William the Conqueror. A dodo decides that the best thing to dry them off would be a Caucus-Race, which consists of everyone running in a circle with no clear winner. Alice eventually frightens all the animals away, unwittingly, by talking about her (moderately ferocious) cat.Chapter Four – The Rabbit Sends a Little Bill: White Rabbit appears again in search of the Duchess's gloves and fan. Mistaking her for his maidservant, Mary Ann, Rabbit orders Alice to go into the house and retrieve them. Inside the house she finds another little bottle and drinks from it, immediately beginning to grow again. The horrified Rabbit orders his gardener, Bill the Lizard, to climb on the roof and go down the chimney. Outside, Alice hears the voices of animals that have gathered to gawk at her giant arm. The crowd hurls pebbles at her, which turn into little cakes. Alice eats them, and they reduce her again in size.Chapter Five – Advice from a Caterpillar: Alice comes upon a mushroom and sitting on it is a blue caterpillar smoking a hookah. Caterpillar questions Alice, who begins to admit to her current identity crisis, compounded by her inability to remember a poem. Before crawling away, the caterpillar tells Alice that one side of the mushroom will make her taller and the other side will make her shorter. She breaks off two pieces from the mushroom. One side makes her shrink smaller than ever, while another causes her neck to grow high into the trees, where a pigeon mistakes her for a serpent. With some effort, Alice brings herself back to her normal height. She stumbles upon a small estate and uses the mushroom to reach a more appropriate height. "
