// This function runs after the common function,
// `src/execute/index.js#buildRequest`
import assign from 'lodash/assign'
import get from 'lodash/get'
import isPlainObject from 'lodash/isPlainObject'
import isArray from 'lodash/isArray'
import btoa from 'btoa'
import {Buffer} from 'buffer/'
import crypto  from 'crypto'
import {mergeInQueryOrForm} from '../../http' // Used to get the computed URL for endpoint used to compute the checksum

export default function (options, req) {
  const {
    operation,
    requestBody,
    securities,
    spec,
    attachContentTypeForEmptyPayload
  } = options

  let {
    requestContentType
  } = options

  const tempRequest = assign({}, req)
  mergeInQueryOrForm(tempRequest) // set req.url with full params
  const pathName = tempRequest.url.replace(options.server, "")

  req = applySecurities({request: req, securities, operation, spec, pathName, requestBody, requestContentType})

  const requestBodyDef = operation.requestBody || {}
  const requestBodyMediaTypes = Object.keys(requestBodyDef.content || {})
  const isExplicitContentTypeValid = requestContentType
  && requestBodyMediaTypes.indexOf(requestContentType) > -1

  // for OAS3: set the Content-Type
  if (requestBody || attachContentTypeForEmptyPayload) {
    // does the passed requestContentType appear in the requestBody definition?

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
  else if (requestContentType && isExplicitContentTypeValid) {
    req.headers['Content-Type'] = requestContentType
  }

  // for OAS3: add requestBody to request
  if (requestBody) {
    if (requestContentType) {
      if (requestBodyMediaTypes.indexOf(requestContentType) > -1) {
        // only attach body if the requestBody has a definition for the
        // contentType that has been explicitly set
        if (requestContentType === 'application/x-www-form-urlencoded' || requestContentType.indexOf('multipart/') === 0) {
          if (typeof requestBody === 'object') {
            req.form = {}
            Object.keys(requestBody).forEach((k) => {
              const val = requestBody[k]
              let newVal

              let isFile

              if (typeof File !== 'undefined') {
                isFile = val instanceof File // eslint-disable-line no-undef
              }

              if (typeof Blob !== 'undefined') {
                isFile = isFile || val instanceof Blob // eslint-disable-line no-undef
              }

              if (typeof Buffer !== 'undefined') {
                isFile = isFile || Buffer.isBuffer(val)
              }

              if (typeof val === 'object' && !isFile) {
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
export function applySecurities({request, securities = {}, operation = {}, spec, pathName, requestBody, requestContentType}) {
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
            const {apiKey, secretKey} = value
            result.headers = Object.assign({}, result.headers,
              generateHeaders(apiKey, secretKey, pathName, requestBody, requestContentType, result)
            )
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

function md5(requestBody) {
  let localRequestBody = requestBody

  if (localRequestBody) {
    if (isPlainObject(localRequestBody) || isArray(localRequestBody)) {
      localRequestBody = JSON.stringify(localRequestBody)
    }

    return crypto.createHash('md5').update(localRequestBody).digest('base64')
  }
  return ''
}

function authHash(secretKey, endpoint, contentMd5, date, requestContentType) {
  const data = [requestContentType, contentMd5, endpoint, date]
  return crypto.createHmac('sha1', secretKey).update(data.join(',')).digest('base64')
}

function generateHeaders(apiKey, secretKey, pathName, requestBody, requestContentType,
  {method, headers: {Accept: responseContentType}}) {
  const date = new Date().toUTCString()
  const contentMd5 = md5(requestBody)
  const hash = authHash(secretKey, encodeURI(pathName), contentMd5, date, requestContentType)

  return {
    'Content-MD5': contentMd5,
    Date: date,
    Authorization: `APIAuth ${apiKey}:${hash}`
  }
}
