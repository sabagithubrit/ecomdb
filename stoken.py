from itsdangerous import URLSafeTimedSerializer
secret_key='codesnm'
def endata(data):
    serializer=URLSafeTimedSerializer(secret_key)
    return serializer.dumps(data,salt='Extrasnm')
def dndata(data):
    serializer=URLSafeTimedSerializer(secret_key)
    return serializer.loads(data,salt='Extrasnm')
