from maestrosocket import MaestroSocket

if __name__ == "__main__":
    sock = MaestroSocket('0.0.0.0', 10000)
    sock.client_loop()