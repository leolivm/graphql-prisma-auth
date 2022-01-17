import 'reflect-metadata'
import { ApolloServer } from 'apollo-server'
import { buildSchema } from 'type-graphql'

import { context } from './context'
import { UserResolver } from './UserResolver'

const app = async () => {
  const schema = await buildSchema({ resolvers: [UserResolver] })

  new ApolloServer({ schema, context }).listen({ port: 3333 }, () =>
    console.log('Server is running'),
  )
}

app()
