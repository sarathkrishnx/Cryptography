list = [
    
    
    {
        "name":"sarath",
        "age":20
    },
    {
        "name":"nish",
        "age":21
    }
    
]


name = input("enter name : ")

for l in list:
    if name in l['name']:
        print(f"name:{l['name']}\nage:{l['age']}")