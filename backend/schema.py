import graphene
import graphql_jwt
import users.schema
import assets.schema
import scans.schema

class Query(
    users.schema.Query, assets.schema.Query, scans.schema.Query, graphene.ObjectType,
):
    pass
class Mutation(users.schema.Mutation, assets.schema.Mutation, scans.schema.Mutation,  graphene.ObjectType):
    token_auth = graphql_jwt.ObtainJSONWebToken.Field()
    verify_token = graphql_jwt.Verify.Field()
    refresh_token = graphql_jwt.Refresh.Field()

schema = graphene.Schema(query=Query, mutation=Mutation)