from maestrosocket import MaestroSocket

if __name__ == "__main__":
    sock = MaestroSocket('0.0.0.0', 20000)
    sock.client_loop()