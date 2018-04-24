// This function runs after the common function,
// `src/execute/index.js#buildRequest`
import assign from 'lodash/assign'
import get from 'lodash/get'
import btoa from 'btoa'
import crypto  from 'crypto'
import {mergeInQueryOrForm} from '../../http' // Used to get the computed URL for endpoint used to compute the checksum

export default function (options, req) {
  const {
    operation,
    requestBody,
    securities,
    spec
  } = options

  let {
    requestContentType
  } = options

  const tempRequest = assign({}, req)
  mergeInQueryOrForm(tempRequest) // set req.url with full params
  const pathName = tempRequest.url.replace(options.server, "")

  req = applySecurities({request: req, securities, operation, spec, pathName, requestBody})

  const requestBodyDef = operation.requestBody || {}
  const requestBodyMediaTypes = Object.keys(requestBodyDef.content || {})

  // for OAS3: set the Content-Type
  if (requestBody) {
    // does the passed requestContentType appear in the requestBody definition?
    const isExplicitContentTypeValid = requestContentType
      && requestBodyMediaTypes.indexOf(requestContentType) > -1

    if (requestContentType && isExplicitContentTypeValid) {
      req.headers['Content-Type'] = requestContentType
    }
    else if (!requestContentType) {
      const firstMediaType = requestBodyMediaTypes[0]
      if (firstMediaType) {
        req.headers['Content-Type'] = firstMediaType
        requestContentType = firstMediaType
      }
    }
  }

  // for OAS3: add requestBody to request
  if (requestBody) {
    if (requestContentType) {
      if (requestBodyMediaTypes.indexOf(requestContentType) > -1) {
        // only attach body if the requestBody has a definition for the
        // contentType that has been explicitly set
        if (requestContentType === 'application/x-www-form-urlencoded') {
          if (typeof requestBody === 'object') {
            req.form = {}
            Object.keys(requestBody).forEach((k) => {
              const val = requestBody[k]
              let newVal

              if (typeof val === 'object') {
                if (Array.isArray(val)) {
                  newVal = val.toString()
                }
                else {
                  newVal = JSON.stringify(val)
                }
              }
              else {
                newVal = val
              }

              req.form[k] = {
                value: newVal
              }
            })
          }
          else {
            req.form = requestBody
          }
        }
        else {
          req.body = requestBody
        }
      }
    }
    else {
      req.body = requestBody
    }
  }

  return req
}

// Add security values, to operations - that declare their need on them
// Adapted from the Swagger2 implementation
export function applySecurities({request, securities = {}, operation = {}, spec, pathName, requestBody}) {
  const result = assign({}, request)
  const {authorized = {}} = securities
  const security = operation.security || spec.security || []
  const isAuthorized = authorized && !!Object.keys(authorized).length
  const securityDef = get(spec, ['components', 'securitySchemes']) || {}

  result.headers = result.headers || {}
  result.query = result.query || {}

  if (!Object.keys(securities).length || !isAuthorized || !security ||
      (Array.isArray(operation.security) && !operation.security.length)) {
    return request
  }

  security.forEach((securityObj, index) => {
    for (const key in securityObj) {
      const auth = authorized[key]
      const schema = securityDef[key]

      if (!auth) {
        continue
      }

      const value = auth.value || auth
      const {type} = schema

      if (auth) {
        if (type === 'apiKey') {
          if (schema.in === 'query') {
            result.query[schema.name] = value
          }
          if (schema.in === 'header') {
            result.headers[schema.name] = value
          }
          if (schema.in === 'cookie') {
            result.cookies[schema.name] = value
          }
        }
        else if (type === 'http') {
          if (schema.scheme === 'basic') {
            const {username, password} = value
            const encoded = btoa(`${username}:${password}`)
            result.headers.Authorization = `Basic ${encoded}`
          }

          if (schema.scheme === 'bearer') {
            result.headers.Authorization = `Bearer ${value}`
          }

          if (schema.scheme === 'hmac-sha1') {
            const { apiKey, secretKey } = value
            result.headers = generateHeaders(apiKey, secretKey, pathName, requestBody)
          }
        }
        else if (type === 'oauth2') {
          const token = auth.token || {}
          const accessToken = token.access_token
          let tokenType = token.token_type

          if (!tokenType || tokenType.toLowerCase() === 'bearer') {
            tokenType = 'Bearer'
          }

          result.headers.Authorization = `${tokenType} ${accessToken}`
        }
      }
    }
  })

  return result
}

const CONTENT_TYPE = 'application/json'

function md5(requestBody) {
  if (requestBody) {
    return crypto.createHash('md5').update(requestBody).digest('base64')
  }
  return ''
}

function authHash(secretKey, endpoint, contentMd5, date) {
  const data = [CONTENT_TYPE, contentMd5, endpoint, date].join(',')

  return crypto.createHmac('sha1', secretKey).update(data).digest('base64')
}

function generateHeaders(apiKey, secretKey, pathName, requestBody) {
  const date = new Date().toUTCString()
  const contentMd5 = md5(requestBody)
  const hash = authHash(secretKey, pathName, contentMd5, date)

  return {
    'Accept': 'application/vnd.regalii.v3.2+json',
    'Authorization': `APIAuth ${apiKey}:${hash}`,
    'Content-MD5': contentMd5,
    'Content-Type': CONTENT_TYPE,
    'X-Date': date
  }
}