import time
import socket
import threading
console_lock = threading.Lock()



class Packet:
    def __init__(self, flag, order, crc, data):
        self.flag = flag
        self.order = order
        self.crc = crc
        self.data = data



def fragment_message(message: bytes) -> list:
    global fragment_size
    return [message[i:i + fragment_size] for i in range(0, len(message), fragment_size)]

def create_message_packets(packets: list) -> list:


def send_mode():
    pass


def recieve_mode():
    global ip, port, sock
    while True:
        data, addr = sock.recvfrom(1024)  # buffer size is 1024 bytes
        console_lock.acquire()
        print(addr, data)
        #sock.sendto("yooo".encode(), addr)
        console_lock.release()



def switch_mode():
    global mode
    if mode == "send":
        mode = "receive"
    else:
        mode = "send"


def send_file(args):
    pass


def send_msg(args):
    arguments = args.split(" ", maxsplit=2)
    console_lock.acquire()
    print("SENDING MESSAGE TO" , arguments[0], " PORT:", arguments[1], " MESSAGE: ", arguments[2])
    console_lock.release()
    global sock

    msg_frag = fragment_message(arguments[2].encode())
    for frag in msg_frag:
        sock.sendto(frag, (arguments[0], int(arguments[1])))




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

        if command[0].lower() == "mode" or command[0].lower() == "mo":
            switch_mode()
            print(mode)

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

    hub()
    # alicemessage = "Chapter One – Down the Rabbit Hole: Alice, a seven-year-old girl, is feeling bored and drowsy while sitting on the riverbank with her elder sister. She notices a talking, clothed white rabbit with a pocket watch run past. She follows it down a rabbit hole where she suddenly falls a long way to a curious hall with many locked doors of all sizes. She finds a little key to a door too small for her to fit through, but through it, she sees an attractive garden. She then discovers a bottle on a table labelled DRINK ME, the contents of which cause her to shrink too small to reach the key which she had left on the table. She subsequently eats a cake labelled  in currants as the chapter closes.Chapter Two – The Pool of Tears: The chapter opens with Alice growing to such a tremendous size that her head hits the ceiling. Unhappy, Alice begins to cry and her tears literally flood the hallway. After she picks up a fan that causes her to shrink back down, Alice swims through her own tears and meets a mouse, who is swimming as well. Alice, thinking he may be a French mouse, tries to make small talk with him in elementary French. Her opening gambit Où est ma chatte? (transl.Where is my cat?), however, offends the mouse, who then tries to escape her.Chapter Three – The Caucus Race and a Long Tale: The sea of tears becomes crowded with other animals and birds that have been swept away by the rising waters. Alice and the other animals convene on the bank and the question among them is how to get dry again. Mouse gives them a very dry lecture on William the Conqueror. A dodo decides that the best thing to dry them off would be a Caucus-Race, which consists of everyone running in a circle with no clear winner. Alice eventually frightens all the animals away, unwittingly, by talking about her (moderately ferocious) cat.Chapter Four – The Rabbit Sends a Little Bill: White Rabbit appears again in search of the Duchess's gloves and fan. Mistaking her for his maidservant, Mary Ann, Rabbit orders Alice to go into the house and retrieve them. Inside the house she finds another little bottle and drinks from it, immediately beginning to grow again. The horrified Rabbit orders his gardener, Bill the Lizard, to climb on the roof and go down the chimney. Outside, Alice hears the voices of animals that have gathered to gawk at her giant arm. The crowd hurls pebbles at her, which turn into little cakes. Alice eats them, and they reduce her again in size.Chapter Five – Advice from a Caterpillar: Alice comes upon a mushroom and sitting on it is a blue caterpillar smoking a hookah. Caterpillar questions Alice, who begins to admit to her current identity crisis, compounded by her inability to remember a poem. Before crawling away, the caterpillar tells Alice that one side of the mushroom will make her taller and the other side will make her shorter. She breaks off two pieces from the mushroom. One side makes her shrink smaller than ever, while another causes her neck to grow high into the trees, where a pigeon mistakes her for a serpent. With some effort, Alice brings herself back to her normal height. She stumbles upon a small estate and uses the mushroom to reach a more appropriate height. "


