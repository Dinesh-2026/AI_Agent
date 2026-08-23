# n = 5
# for i in range(n):
#     for j in range(n-i+1):
#         print(" ", end="")
#     for k in range(i+1):
#         print("*",end = " ")
#     print()

# for i in range(n,-1,-1):
#     for j in range(n-i+2):
#         print(" ",end="")
#     for k in range(i):
#         print("*",end = " ")
#     print()

# n = 5 
# for i in range(n):
#     for j in range(i+1):
#         print("*",end = " ")
#     print()
# class car:
#     following = 0
#     def __init__(self,make,model,year):
#         self.make = make
#         self.model = model
#         self.year = year

#     def good_car(self):
#         if self.year >= 2024:
#             return f"its a good car, {self.model} "

#     def bad_car(self):
#         self.following += 1
#         if self.year <= 2024:
#             return  f"its a bad car, {self.model},and its {self.following}"
        
# car_1 = car("roys royce","phantom",2024)

# print(car_1.good_car())
# print(car_1.following)

# print(car_1.bad_car())
# print(car_1.following)
class human:
    def __init__(self,name,age):
        self.name = name
        self.age = age
class student(human):
    def __init__(self,a,b,grade):
        super().__init__(a,b)
        self.grade = grade
        
        
student_1 = student("john",20,"A")
print(student_1.name)
print(student_1.age)
print(student_1.grade)
print(isinstance(student_1,human))
print(issubclass(student,human))