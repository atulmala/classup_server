import os
from django.http import JsonResponse

import graphene
import graphql_jwt
import jwt

from graphene_django.views import GraphQLView
from datetime import datetime, timedelta

from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST


class Query(graphene.ObjectType):
    hello = graphene.String(default_value="Hi!")

class UserType(graphene.ObjectType):
    id = graphene.ID()
    username = graphene.String()
    first_name = graphene.String()
    last_name = graphene.String()
    groups = graphene.List(graphene.String)
    is_active = graphene.Boolean()

    def resolve_groups(self, info):
        return [group.name for group in self.groups.all()] 

class TokenAuthWithUser(graphene.Mutation):
    token = graphene.String()
    user = graphene.Field(UserType)

    class Arguments:
        username = graphene.String(required=True)
        password = graphene.String(required=True)

    @staticmethod
    def mutate(root, info, username, password):
        user = authenticate(username=username, password=password)
        if user is None:
            raise Exception('Invalid credentials')

        payload = {
            'user_id': str(user.id),
            'exp': datetime.utcnow() + timedelta(days=1)  # Token expiration time
        }
        
        jwt_secret_key = os.environ.get("JWT_SECRET_KEY")
        if jwt_secret_key is None:
            raise Exception("JWT secret key is not set. Please set the JWT_SECRET_KEY environment variable.")

        # Generate JWT token
        token = jwt.encode(payload, jwt_secret_key, algorithm='HS256')
        print('login succcessful and token generated: %s' % token)
        
        return TokenAuthWithUser(token=token, user=user)

class Mutation(graphene.ObjectType):
    token_auth_with_user = TokenAuthWithUser.Field()
    verify_token = graphql_jwt.Verify.Field()
    refresh_token = graphql_jwt.Refresh.Field()

schema = graphene.Schema(query=Query, mutation=Mutation)

@csrf_exempt
@require_POST
def graphql_view(request):
    view = GraphQLView.as_view(schema=schema, graphiql=True)
    return view(request)

@csrf_exempt
def introspect_schema(request):
    introspection = schema.introspect()
    return JsonResponse(introspection)
