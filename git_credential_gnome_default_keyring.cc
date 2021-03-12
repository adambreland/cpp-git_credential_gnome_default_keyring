#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <map>
#include <regex>
#include <string>
#include <utility>

// This header is not configured to be used automatically in both C and C++
// programs.
extern "C"
{
  #include <libsecret/secret.h>
}

namespace {

constexpr const char* argument_number_error_message_prefix
  {"An action argument was not provided to "};
constexpr const char* exception_message {"An uncaught exception occurred.\n"};

// This regular expression allows the splitting of an input line based on the
// first occurrence of an equal sign after a non-empty character sequence which
// does not contain an equal sign when the input line is read from left to
// right.
// (.+?) A non-greedy sequence of one or more characters which is treated as a
//       a submatch.
// =     An equal sign.
// (.*)  A greedy sequence of zero or more characters which is treated as a
//       submatch.
const std::regex split_input {R"((.+?)=(.*))"};

// This regular expression parses a secret string into a username and password.
// It is assumed that the username is separated from the password by a colon.
const std::regex split_secret_string{R"((.+?):(.*))"};

// Git forbids values from possessing newline or null characters.
const std::regex forbidden_value_chars {R"([\0\n])"};

const std::string protocol_str {"protocol"};
const std::string host_str {"host"};
const std::string path_str {"path"};
const std::string username_str {"username"};
const std::string password_str {"password"};

//    The following two classes are typical resource management classes. Each
// is a typical management class for a resource which is accessed through a
// pointer once it is acquired and which must be released by calling a special
// function.
//    GErrorManager manages a pointer to a structure. This allows operators
// * and -> to make sense. SecretStringManager manages a C string with special
// release requirements. Operators * and -> are not appropriate in this case.
// Both classes are only used with pointers to the appropriate, non-constant
// type.
class SecretStringManager
{
 public:
  SecretStringManager() = default;
  inline explicit SecretStringManager(gchar* secret_string_ptr) noexcept
  : secret_string_ptr_ {secret_string_ptr}
  {}

  // Move-only
  SecretStringManager(const SecretStringManager&) = delete;
  inline SecretStringManager(SecretStringManager&& secret_string_manager) noexcept
  : secret_string_ptr_ {secret_string_manager.secret_string_ptr_}
  {
    secret_string_manager.secret_string_ptr_ = nullptr;
  }
  SecretStringManager& operator=(const SecretStringManager&) = delete;
  inline SecretStringManager& operator=(
    SecretStringManager&& secret_string_manager) noexcept
  {
    gchar* temp_ptr {secret_string_manager.secret_string_ptr_};
    secret_string_manager.secret_string_ptr_ = secret_string_ptr_;
    secret_string_ptr_ = temp_ptr;
    return *this;
  }

  inline gchar* get() const noexcept
  {
    return secret_string_ptr_;
  }

  inline gchar* release() noexcept
  {
    gchar* temp_ptr {secret_string_ptr_};
    secret_string_ptr_ = nullptr;
    return temp_ptr;
  }

  inline explicit operator bool() const noexcept
  {
    return secret_string_ptr_;
  }

  inline ~SecretStringManager()
  {
    if(secret_string_ptr_)
    {
      secret_password_free(secret_string_ptr_);
    }
  }

 private:
  gchar* secret_string_ptr_ {nullptr};
};

class GErrorManager
{
 public:
  GErrorManager() = default;
  inline explicit GErrorManager(GError* g_error_ptr) noexcept
  : g_error_ptr_ {g_error_ptr}
  {}

  // Move-only
  GErrorManager(const GErrorManager&) = delete;
  inline GErrorManager(GErrorManager&& g_error_manager) noexcept
  : g_error_ptr_ {g_error_manager.g_error_ptr_}
  {
    g_error_manager.g_error_ptr_ = nullptr;
  }
  GErrorManager& operator=(const GErrorManager&) = delete;

  inline GErrorManager& operator=(
    GErrorManager&& g_error_manager) noexcept
  {
    GError* temp_ptr {g_error_manager.g_error_ptr_};
    g_error_manager.g_error_ptr_ = g_error_ptr_;
    g_error_ptr_ = temp_ptr;
    return *this;
  }

  inline GError* get() const noexcept
  {
    return g_error_ptr_;
  }

  inline GError* release() noexcept
  {
    GError* temp_ptr {g_error_ptr_};
    g_error_ptr_ = nullptr;
    return temp_ptr;
  }

  inline explicit operator bool() const noexcept
  {
    return g_error_ptr_;
  }

  inline GError& operator*() const noexcept
  {
    return *g_error_ptr_;
  }

  inline GError* operator->() const noexcept
  {
    return g_error_ptr_;
  }

  inline ~GErrorManager()
  {
    if(g_error_ptr_)
    {
      g_error_free(g_error_ptr_);
    }
  }

 private:
  GError* g_error_ptr_ {nullptr};
};

void PrintGErrorMessageAndRelease(GError* g_error_ptr)
{
  if(g_error_ptr)
  {
    GErrorManager g_error {g_error_ptr};
    std::cerr << g_error->message << '\n';
  } // Releases the allocated GError structure.
}

} // namespace

int main(int argc, char* argv[])
{
  try {
  // This credential helper expects no options and expects an action keyword as
  // the first non-option argument. The allowed action keywords are "get",
  // "store", and "erase".
  if(argc == 0)
  {
    std::cerr << argument_number_error_message_prefix <<
      "git-credential-gnome-default-keyring.\n";
    return EXIT_FAILURE;
  }
  if(argc < 2)
  {
    std::cerr << argument_number_error_message_prefix << argv[0] << ".\n";
    return EXIT_FAILURE;
  }
  char* action_keyword_ptr {argv[1]};
  std::string input_buffer {};
  // Initialize the buffer.
  std::getline(std::cin, input_buffer);
  std::map<std::string, std::string> request_attribute_map {};
  std::map<std::string, std::string>::const_iterator map_cend
    {request_attribute_map.cend()};
  std::smatch match_result {};

  // Reads the lines which were sent, and splits them into names and values.
  // Git may terminate a sequence of request lines with an empty line or
  // end-of-file.
  while(true)
  {
    if(std::cin && input_buffer.size())
    {
      if(std::regex_match(input_buffer, match_result, split_input))
      {
        std::string attribute {match_result[1].first, match_result[1].second};
        std::string value {match_result[2].first, match_result[2].second};
        if(std::regex_search(attribute, forbidden_value_chars) ||
           std::regex_search(value, forbidden_value_chars))
        {
          std::cerr << "A prohibited value was found in the name or value of "
            "an input line. Names and values cannot contain the newline "
            "character or the null character.\n";
          return EXIT_FAILURE;
        }
        request_attribute_map[std::move(attribute)] = std::move(value);
        std::getline(std::cin, input_buffer); // Continue.
      }
      else
      {
        std::cerr << "An input line did not match the expected "
          "<attribute>=<value> pattern.\n";
        return EXIT_FAILURE;
      }
    }
    else if(!std::cin && !std::cin.eof())
    {
      std::cerr << "An input line could not be read due to an underlying "
        "error\n.";
      return EXIT_FAILURE;
    }
    else
    {
      break;
    }
  }

  // Ensures that a host and prototcol attribute were sent. These are
  // necessary in all cases.
  std::map<std::string, std::string>::const_iterator host_iter {};
  std::map<std::string, std::string>::const_iterator protocol_iter {};
  if(((host_iter = request_attribute_map.find(host_str)) == map_cend) ||
     ((protocol_iter = request_attribute_map.find(protocol_str)) == map_cend))
  {
    std::cerr << "At least one of the host or protocol attributes was not "
      "provided.\n";
    return EXIT_FAILURE;
  }
  
  // Establishes common state once it is known that the program can contine.
  const SecretSchema path_schema
  {
    /* name */  "path_schema",
    /* flags */ SECRET_SCHEMA_DONT_MATCH_NAME,
    /* attributes */
    {
      {protocol_str.data(), SECRET_SCHEMA_ATTRIBUTE_STRING},
      {host_str.data(), SECRET_SCHEMA_ATTRIBUTE_STRING},
      {path_str.data(), SECRET_SCHEMA_ATTRIBUTE_STRING},
      {nullptr}
    }
  };
  const SecretSchema no_path_schema
  {
    /* name */  "no_path_schema",
    /* flags */ SECRET_SCHEMA_DONT_MATCH_NAME,
    /* attributes */
    {
      {protocol_str.data(), SECRET_SCHEMA_ATTRIBUTE_STRING},
      {host_str.data(), SECRET_SCHEMA_ATTRIBUTE_STRING},
      {nullptr}
    }
  };
  std::map<std::string, std::string>::const_iterator path_iter
    {request_attribute_map.find(path_str)};
  bool path_present {path_iter != map_cend};

  // Selects an action based on the action keyword (an if-else-if ladder on
  // the keyword).
  if(std::strcmp(action_keyword_ptr, "get") == 0)
  {
    // Attempts to retrieve credentials.
    SecretStringManager retrieved_secret {};
    // These two if statements contain the only logic of the program which
    // uses the Libsecret API.
    if(path_present)
    {
      // Tries to retrieve a password string from credentials which match the
      // protocol-host-path schema.
      GError* g_error_ptr {nullptr};
      retrieved_secret = SecretStringManager {secret_password_lookup_sync(
        /* schema (ptr) */ &path_schema,
        /* cancellable */ nullptr,
        /* error */ &g_error_ptr, // Result argument
        // Starts the variadic list of names and values.
        protocol_str.data(),
        protocol_iter->second.data(),
        host_str.data(),
        host_iter->second.data(),
        path_str.data(),
        path_iter->second.data(),
        // Required terminal NULL.
        nullptr
      )};
      if(g_error_ptr)
      {
        PrintGErrorMessageAndRelease(g_error_ptr);
        return EXIT_FAILURE;
      }
    }
    // Checks if credentials were not found in the previous step (either
    // because they were absent or because the step wasn't performed).
    if(!retrieved_secret)
    {
      // Look for credentials which match the protocol-host schema.
      GError* g_error_ptr {nullptr};
      retrieved_secret = SecretStringManager {secret_password_lookup_sync(
        /* schema (ptr) */ &no_path_schema,
        /* cancellable */ nullptr,
        /* error */ &g_error_ptr, // Result argument
        // Starts the variadic list of names and values.
        protocol_str.data(),
        protocol_iter->second.data(),
        host_str.data(),
        host_iter->second.data(),
        // Required terminal NULL.
        nullptr
      )};
      if(g_error_ptr)
      {
        PrintGErrorMessageAndRelease(g_error_ptr);
        return EXIT_FAILURE;
      }
    }
    if(retrieved_secret)
    {
      // Splits the secret string into a username and value.
      std::cmatch username_value_match {};
      if(std::regex_match(retrieved_secret.get(), username_value_match,
        split_secret_string))
      {
        // Validates the username and value.
        std::string username {username_value_match[1].first,
          username_value_match[1].second};
        std::string password {username_value_match[2].first,
          username_value_match[2].second};
        if(std::regex_search(username, forbidden_value_chars) ||
           std::regex_search(password, forbidden_value_chars))
        {
          std::cerr << "A prohibited character was found in the retrieved "
            "username or password. Neither can contain the newline character "
            "or the null character.\n";
          return EXIT_FAILURE;
        }
        // Adds the username and password to the attribute map.
        request_attribute_map[username_str] = std::move(username);
        request_attribute_map[password_str] = std::move(password);
      }
      else
      {
        std::cerr << "A retrieved secret string was in an unknown format. The "
          "secret string must be in the form:\nusername:password\n";
        return EXIT_FAILURE;
      }
      // Sends the attributes to Git.
      for(std::map<std::string, std::string>::const_iterator iter
        {request_attribute_map.cbegin()}; iter != map_cend; ++iter)
      {
        std::cout << iter->first << "=" << iter->second << '\n';
      }
      // End-of-file will be used to terminate the response to Git.
    }
    else
    {
      std::cerr << "Credentials were not found.\n";
      return EXIT_FAILURE;
    }
  }
  else if(std::strcmp(action_keyword_ptr, "store") == 0)
  {
    // Checks that a username and password were provided.
    std::map<std::string, std::string>::const_iterator username_iter {};
    std::map<std::string, std::string>::const_iterator password_iter {};
    if(((username_iter = request_attribute_map.find(username_str)) == map_cend) ||
        ((password_iter = request_attribute_map.find(password_str)) == map_cend))
    {
      std::cerr << "At least one of the username and password were not "
        "provided.\n";
      return EXIT_FAILURE;
    }
    std::string password {username_iter->second};
    password.append(1, ':').append(password_iter->second);
    std::string store_label {host_iter->second};
    GError* g_error_ptr {nullptr};
    if(path_present)
    {
      store_label.append(1, '/').append(path_iter->second);
      if(!secret_password_store_sync(
        /* schema */ &path_schema,
        /* collection */ SECRET_COLLECTION_DEFAULT,
        /* label */ store_label.data(),
        /* password */ password.data(),
        /* cancellable */ nullptr,
        /* error */ &g_error_ptr,
        // Starts the variadic attribute name value pair list.
        protocol_str.data(),
        protocol_iter->second.data(),
        host_str.data(),
        host_iter->second.data(),
        path_str.data(),
        path_iter->second.data(),
        // Required terminal NULL.
        nullptr
      ))
      {
        PrintGErrorMessageAndRelease(g_error_ptr);
        return EXIT_FAILURE;
      }
    }
    else
    {
      if(!secret_password_store_sync(
        /* schema */ &no_path_schema,
        /* collection */ SECRET_COLLECTION_DEFAULT,
        /* label */ store_label.data(),
        /* password */ password.data(),
        /* cancellable */ nullptr,
        /* error */ &g_error_ptr,
        // Starts the variadic attribute name value pair list.
        protocol_str.data(),
        protocol_iter->second.data(),
        host_str.data(),
        host_iter->second.data(),
        // Required terminal NULL.
        nullptr
      ))
      {
        PrintGErrorMessageAndRelease(g_error_ptr);
        return EXIT_FAILURE;
      }
    }
  }
  else if(std::strcmp(action_keyword_ptr, "erase") == 0)
  {
    GError* g_error_ptr {nullptr};
    if(path_present)
    {
      if(!secret_password_clear_sync(
        /* schema */ &path_schema,
        /* cancellable */ nullptr,
        /* error */ &g_error_ptr,
        // Starts the variadic attribute name value pair list.
        protocol_str.data(),
        protocol_iter->second.data(),
        host_str.data(),
        host_iter->second.data(),
        path_str.data(),
        path_iter->second.data(),
        // Required terminal NULL.
        nullptr
      ))
      {
        if(g_error_ptr)
        {
          PrintGErrorMessageAndRelease(g_error_ptr);
          return EXIT_FAILURE;
        }
      }
    }
    else
    {
      if(!secret_password_clear_sync(
        /* schema */ &no_path_schema,
        /* cancellable */ nullptr,
        /* error */ &g_error_ptr,
        // Starts the variadic attribute name value pair list.
        protocol_str.data(),
        protocol_iter->second.data(),
        host_str.data(),
        host_iter->second.data(),
        // Required terminal NULL.
        nullptr
      ))
      {
        if(g_error_ptr)
        {
          PrintGErrorMessageAndRelease(g_error_ptr);
          return EXIT_FAILURE;
        }
      }
    }
  }
  else // Unrecognized action.
  {
    std::cerr << "An unexpected action argument was provided: "
      << action_keyword_ptr << "\nThe allowed actions are get, store, and "
      "erase.\n";
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
  }
  catch(std::exception& e)
  {
    std::cerr << exception_message << e.what() << '\n';
    throw;
  }
  catch(...)
  {
    std::cerr << exception_message;
    throw;
  }
}
