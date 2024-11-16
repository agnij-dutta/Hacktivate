import pprint
from github import Github


def get_git_dat(uname, gittoken=''):

    g = Github(gittoken)
    user = g.get_user(uname)


    # user_hmap = None
    name, bio, followers, following, company, blog = user.name, user.bio, user.followers_url, user.following_url, user.company, user.blog
    git_dat = {
        # 'name': name,
        # 'bio': bio,
        # 'followers': followers,
        # 'following': following,
        # 'company' : company,
        # 'blog': blog,
        # 'public_repos': user.public_repos,
        # 'public_gists' : user.public_gists,
        # 'last_updated': user.last_modified_datetime,
        # 'collabs' : user.collaborators,
        "new":user.raw_data
    }

    pprint.pprint(git_dat)

get_git_dat('agnij-dutta')