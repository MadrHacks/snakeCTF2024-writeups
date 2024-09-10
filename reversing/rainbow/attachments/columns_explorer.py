


def read_matrix_from_file(filename):
    with open(filename, 'rb') as file:
        width = int.from_bytes(file.read(2))
        height = int.from_bytes(file.read(2))
        steps = int.from_bytes(file.read(4))

        matrix = []
        for _ in range(width):
            matrix.append(list(file.read(height).translate(
                bytes.maketrans(bytes([83, 53, 32, 115]), bytes([0, 1, 2, 3])))))

        print(width, height, steps)
        return matrix, steps

matrix, steps = read_matrix_from_file('./challenge/circuit')

c = 1

c1 = [''.join(map(str,x[40*c:40*(c+1)])).replace('0',' ') for x in matrix]
c = 2
c2 = [''.join(map(str,x[40*c:40*(c+1)])).replace('0',' ') for x in matrix]

print('\n'.join(f'{a}    {b}' for a,b in zip(c1,c2)))
