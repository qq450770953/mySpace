from datetime import datetime, timedelta, date

# Create a datetime object
start_date = datetime.now()
print(f"start_date: {start_date}")

# Test correct syntax
print("Correct: isinstance(start_date, (date, datetime))")
print(isinstance(start_date, (date, datetime)))

# Test wrong syntax (should cause error)
try:
    # This is incorrect syntax that would cause the error in our app
    print("Wrong: directly using 'datetime.datetime' attribute")
    print("This would raise: AttributeError: type object 'datetime.datetime' has no attribute 'datetime'")
except Exception as e:
    print(f"Error: {type(e).__name__}: {e}") 