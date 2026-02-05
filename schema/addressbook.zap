# ZAP Schema - Address Book Example
# Demonstrates the clean whitespace-significant syntax

struct Person
  name Text
  email Text
  birthdate Date
  phones List(PhoneNumber)

  struct PhoneNumber
    number Text
    type Type

    enum Type
      mobile
      home
      work

struct Date
  year Int16
  month UInt8
  day UInt8

struct AddressBook
  people List(Person)

interface AddressService
  addPerson (person Person) -> (id Text)
  getPerson (id Text) -> (person Person)
  listPeople () -> (people List(Person))
  searchByName (query Text) -> (results List(Person))
  deletePerson (id Text) -> (success Bool)
