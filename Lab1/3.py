def create_playfair_matrix(keyword):
    """Create a 5x5 Playfair cipher matrix from the given keyword."""
    keyword = keyword.upper().replace('J', 'I')
    matrix = []
    used = set()

    # Add letters from the keyword
    for char in keyword:
        if char not in used and char.isalpha():
            used.add(char)
            matrix.append(char)

    # Add remaining letters of the alphabet
    for char in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if char not in used and char != 'J':
            used.add(char)
            matrix.append(char)

    # Convert to 5x5 matrix
    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def prepare_message(message):
    """Prepare the message for encryption by removing spaces and making digraphs."""
    message = message.upper().replace('J', 'I').replace(' ', '')
    digraphs = []
    i = 0
    while i < len(message):
        a = message[i]
        if i + 1 < len(message):
            b = message[i + 1]
            if a == b:
                digraphs.append(a + 'X')
                i += 1
            else:
                digraphs.append(a + b)
                i += 2
        else:
            digraphs.append(a + 'X')
            i += 1
    return digraphs

def encrypt_digraph(matrix, digraph):
    """Encrypt a digraph using the Playfair cipher rules."""
    pos = {}
    for i, row in enumerate(matrix):
        for j, char in enumerate(row):
            pos[char] = (i, j)

    a, b = digraph
    row_a, col_a = pos[a]
    row_b, col_b = pos[b]

    if row_a == row_b:
        # Same row
        encrypted_a = matrix[row_a][(col_a + 1) % 5]
        encrypted_b = matrix[row_b][(col_b + 1) % 5]
    elif col_a == col_b:
        # Same column
        encrypted_a = matrix[(row_a + 1) % 5][col_a]
        encrypted_b = matrix[(row_b + 1) % 5][col_b]
    else:
        # Rectangle
        encrypted_a = matrix[row_a][col_b]
        encrypted_b = matrix[row_b][col_a]

    return encrypted_a + encrypted_b

def playfair_encrypt(message, keyword):
    """Encrypt the message using the Playfair cipher with the given keyword."""
    matrix = create_playfair_matrix(keyword)
    digraphs = prepare_message(message)
    encrypted_message = ''.join(encrypt_digraph(matrix, digraph) for digraph in digraphs)
    return encrypted_message

# Define the keyword and message
keyword = "GUIDANCE"
message = "The key is hidden under the door pad"

# Encrypt the message
encrypted_message = playfair_encrypt(message, keyword)
print(f"Encrypted message: {encrypted_message}")
