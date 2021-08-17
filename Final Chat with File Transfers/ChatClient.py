import socket
import sys
import os
import select
import getopt
import threading
import errno


HEADER_LENGTH = 10
IP = "127.0.0.1"
PORT = 1234
my_username = input("What is your name? \n")
# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connect to a given ip and port
client_socket.connect((IP, PORT))
# Set connection to non-blocking state, so .recv() call won;t block, just return some exception we'll handle
client_socket.setblocking(True)
# Prepare username and header and send them
# We need to encode username to bytes, then count number of bytes and prepare header of fixed size, that we encode to bytes as well
username = my_username.encode('utf-8')
username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
client_socket.send(username_header + username)

def request_file():
    print('Who owns the file?')
    owner = input(f'{my_username} > ')
    print('Which file do you want?')
    filename = input(f'{my_username} > ')
    message = f"[RequestForFile]:{owner}|{filename}".encode('utf-8')
    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(message_header + message)
def listen():
        # Now we want to loop over received messages (there might be more than one) and print them
        while True:
            try:
                # Receive our "header" containing username length, it's size is defined and constant
                header = client_socket.recv(HEADER_LENGTH)
                # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
                if not len(header):
                    print('Connection closed by the server')
                    sys.exit()
                # Convert header to int value
                length = int(header.decode('utf-8').strip())
                # Receive and decode username
                message = client_socket.recv(length).decode('utf-8')
                # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
                if message.startswith("[RequestedFileData]:"):
                    # File we requested
                    message = message.replace("[RequestedFileData]:", "")
                    data = message.split("|[Sep]|")
                    fileOwnerUser = data[0]
                    filename = data[1]
                    fileData = data[2]
                    f = open(filename, 'wb')
                    fileData = fileData.encode("cp437")
                    f.write(fileData)
                    f.close()
                    print(f'\nDownloaded and saved file {filename} from {fileOwnerUser}')
                elif message.startswith(f"[RequestForFile]:"):
                    # a file request for our client
                    messageBody = message.replace(f"[RequestForFile]:", "")
                    splitMsg = messageBody.split("|")
                    requestedUser = splitMsg[0]
                    filename = splitMsg[1]
                    f = open(filename,'rb')
                    fileData = f.read()
                    fileData = fileData.decode('cp437')
                    fileMsg = f'[RequestedFileData]:{requestedUser}|[Sep]|{filename}|[Sep]|{fileData}'.encode("utf-8")
                    fMessage_Header = f"{len(fileMsg):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(fMessage_Header + fileMsg)
                else:
                    # Print message
                    messageSplit = message.split("|")
                    print(f'\n{messageSplit[0]} > {messageSplit[1]}')
            except IOError as e:
                # This is normal on non blocking connections - when there are no incoming data error is going to be raised
                # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
                # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
                # If we got different error code - something happened
                if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                    print('Reading error: {}'.format(str(e)))
                    sys.exit()
                # We just did not receive anything
            except Exception as e:
                # Any other exception - something happened, exit
                print('Reading error: '.format(str(e)))
                sys.exit()

recv_thread = threading.Thread(target=listen)
recv_thread.start()

while True:
    # Wait for user to input a message
    print('Enter an option (\'m\', \'f\', \'x\'):\n (M)essage (send)\n (F)file (request)\n e(X)it')
    initmessage = input(f'{my_username} > ')
    # If message is not empty - send it
    if initmessage == 'm':
        # Encode message to bytes, prepare header and convert to bytes, like for username above, then send
        print('Enter your message: ')
        message = input(f'{my_username} > ')
        message = message.encode('utf-8')
        message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
        client_socket.send(message_header + message)
        
        #If user requests a file transfer
    elif initmessage == 'f':
        request_file()

        #If user requests to exit        
    elif initmessage == 'x':
        print('Closing your sockets...goodbye')
        sys.exit()
       
