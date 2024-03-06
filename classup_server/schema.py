import graphene
import graphql_jwt
import jwt

from graphene_django.views import GraphQLView
from datetime import datetime, timedelta
from pytz import utc

from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from django.conf import settings

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
        # Assuming groups is a list of strings in your database
        # return self.groups
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
        token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')

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
