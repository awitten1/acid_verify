

#include <cstring>
#include <gtest/gtest.h>
#include "merklecpp/merklecpp.h"
#include "verified_db.h"

TEST(merkle, basic) {
  const char* str = "asdf";
  std::string a = sha256((const unsigned char*)str, strlen(str));
  merkle::Tree::Hash hash(a);

  merkle::Tree tree;
  tree.insert(hash);
  auto root = tree.root();
  auto path = tree.path(0);
  assert(path->verify(root));
}
