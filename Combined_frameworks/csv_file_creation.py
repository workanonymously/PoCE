import csv


def update_csv(file_name, new_row=None):

    try:
        with open(file_name, mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            data = list(reader)

        if new_row:
            data.append(new_row)
            print(f"Added new row: {new_row}")

        with open(file_name, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerows(data)

    except Exception as e:
        print(f"An error occurred: {e}")

